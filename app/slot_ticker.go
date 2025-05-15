// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
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

	slotDuration, ok := spec["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return nil, errors.New("fetch slot duration")
	}

	slotsPerEpoch, ok := spec["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		return nil, errors.New("fetch slots per epoch")
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
