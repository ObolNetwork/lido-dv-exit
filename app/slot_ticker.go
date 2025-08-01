// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/jonboulle/clockwork"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

// newSlotTicker returns a blocking channel that will be populated with new slots in real time.
// It is also populated with the current slot immediately.
//
// Taken from Charon's core/scheduler package.

// parseSpecDuration extracts a duration value from spec data, handling both string and array formats.
func parseSpecDuration(spec map[string]interface{}, key string) (time.Duration, error) {
	value, exists := spec[key]
	if !exists {
		return 0, fmt.Errorf("spec key %s not found", key)
	}

	switch v := value.(type) {
	case time.Duration:
		return v, nil
	case string:
		// Try parsing as number first
		if seconds, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Duration(seconds) * time.Second, nil
		}
		return 0, fmt.Errorf("cannot parse duration from string: %s", v)
	case []interface{}:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				if seconds, err := strconv.ParseInt(str, 10, 64); err == nil {
					return time.Duration(seconds) * time.Second, nil
				}
			}
		}
		return 0, fmt.Errorf("cannot parse duration from array: %v", v)
	default:
		return 0, fmt.Errorf("unexpected type for %s: %T", key, v)
	}
}

// parseSpecUint64 extracts a uint64 value from spec data, handling both direct and array formats.
func parseSpecUint64(spec map[string]interface{}, key string) (uint64, error) {
	value, exists := spec[key]
	if !exists {
		return 0, fmt.Errorf("spec key %s not found", key)
	}

	switch v := value.(type) {
	case uint64:
		return v, nil
	case int64:
		return uint64(v), nil
	case float64:
		return uint64(v), nil
	case string:
		return strconv.ParseUint(v, 10, 64)
	case []interface{}:
		if len(v) > 0 {
			switch firstElem := v[0].(type) {
			case uint64:
				return firstElem, nil
			case int64:
				return uint64(firstElem), nil
			case float64:
				return uint64(firstElem), nil
			case string:
				return strconv.ParseUint(firstElem, 10, 64)
			}
		}
		return 0, fmt.Errorf("cannot parse uint64 from array: %v", v)
	default:
		// Use reflection as fallback for other numeric types
		rv := reflect.ValueOf(v)
		if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
			return uint64(rv.Int()), nil
		}
		if rv.Kind() >= reflect.Uint && rv.Kind() <= reflect.Uint64 {
			return rv.Uint(), nil
		}
		if rv.Kind() == reflect.Float32 || rv.Kind() == reflect.Float64 {
			return uint64(rv.Float()), nil
		}
		return 0, fmt.Errorf("unexpected type for %s: %T", key, v)
	}
}

func newSlotTicker(ctx context.Context, eth2Cl eth2wrap.Client, clock clockwork.Clock) (<-chan core.Slot, error) {
	genesisResp, err := eth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	if err != nil {
		return nil, err
	}
	genesis := genesisResp.Data.GenesisTime

	rawSpec, err := eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return nil, err
	}
	spec := rawSpec.Data

	slotDuration, err := parseSpecDuration(spec, "SECONDS_PER_SLOT")
	if err != nil {
		return nil, errors.Wrap(err, "fetch slot duration")
	}

	slotsPerEpoch, err := parseSpecUint64(spec, "SLOTS_PER_EPOCH")
	if err != nil {
		return nil, errors.Wrap(err, "fetch slots per epoch")
	}

	currentSlot := func() core.Slot {
		chainAge := clock.Since(genesis)
		slot := int64(chainAge / slotDuration)
		startTime := genesis.Add(time.Duration(slot) * slotDuration)

		return core.Slot{
			Slot:          uint64(slot),
			Time:          startTime,
			SlotsPerEpoch: slotsPerEpoch,
			SlotDuration:  slotDuration,
		}
	}

	resp := make(chan core.Slot)
	go func() {
		slot := currentSlot()
		for {
			select {
			case <-ctx.Done():
				return
			case <-clock.After(slot.Time.Sub(clock.Now())):
			}

			// Avoid "thundering herd" problem by skipping slots if missed due
			// to pause-the-world events (i.e. resources are already constrained).
			if clock.Now().After(slot.Next().Time) {
				actual := currentSlot()
				log.Warn(ctx, "Slot(s) skipped", nil, z.U64("actual_slot", actual.Slot), z.U64("expect_slot", slot.Slot))

				slot = actual
			}

			select {
			case <-ctx.Done():
				return
			case resp <- slot:
			}

			slot = slot.Next()
		}
	}()

	return resp, nil
}
