// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import "math/rand/v2"

const (
	// minRetrySlots is the delay after the first failed Obol API request for a key.
	minRetrySlots uint64 = 1
	// maxRetrySlots caps the delay between attempts, a long poll of about 50 minutes on
	// 12s slots for requests that keep failing, e.g. a full exit the cluster hasn't reached
	// the threshold of partial exits for yet.
	maxRetrySlots uint64 = 256
)

// retrySchedule backs off Obol API requests per key exponentially, in slots: each failure
// doubles the delay before the next attempt, from minRetrySlots up to maxRetrySlots, plus up
// to half of it again as jitter so the nodes of a cluster don't poll in lockstep. A success
// resets the key.
type retrySchedule struct {
	next  map[string]uint64 // Slot of the next attempt.
	delay map[string]uint64 // Last delay in slots.
}

func newRetrySchedule() *retrySchedule {
	return &retrySchedule{
		next:  make(map[string]uint64),
		delay: make(map[string]uint64),
	}
}

// due returns true if the key may be attempted at the slot.
func (r *retrySchedule) due(key string, slot uint64) bool {
	return slot >= r.next[key]
}

// failed records a failed attempt of the key at the slot, scheduling the next attempt, and
// returns the slot it is scheduled at.
func (r *retrySchedule) failed(key string, slot uint64) uint64 {
	delay := min(max(r.delay[key]*2, minRetrySlots), maxRetrySlots)
	r.delay[key] = delay

	//nolint:gosec // jitter only, doesn't need a cryptographic source
	r.next[key] = slot + delay + rand.Uint64N(delay/2+1)

	return r.next[key]
}

// succeeded resets the schedule of the key.
func (r *retrySchedule) succeeded(key string) {
	delete(r.next, key)
	delete(r.delay, key)
}
