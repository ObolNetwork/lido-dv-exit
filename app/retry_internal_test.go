// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetrySchedule(t *testing.T) {
	const key = "0xval"

	r := newRetrySchedule()

	// A new key is due right away.
	require.True(t, r.due(key, 0))

	// Each failure doubles the delay, plus up to half of it as jitter, up to the cap.
	slot := uint64(100)
	wantDelay := minRetrySlots

	for range 20 {
		next := r.failed(key, slot)

		require.GreaterOrEqual(t, next, slot+wantDelay)
		require.LessOrEqual(t, next, slot+wantDelay+wantDelay/2)
		require.False(t, r.due(key, next-1))
		require.True(t, r.due(key, next))

		slot = next
		wantDelay = min(wantDelay*2, maxRetrySlots)
	}

	require.Equal(t, maxRetrySlots, r.delay[key])

	// Other keys are scheduled independently.
	require.True(t, r.due("0xother", slot))

	// A success resets the key, so its delay starts over.
	r.succeeded(key)
	require.True(t, r.due(key, 0))

	next := r.failed(key, slot)
	require.Equal(t, minRetrySlots, r.delay[key])
	require.LessOrEqual(t, next, slot+minRetrySlots+minRetrySlots/2)
}

func TestRetryScheduleFailedMax(t *testing.T) {
	const key = "0xval"

	r := newRetrySchedule()

	// The first failure goes straight to the maximum delay.
	slot := uint64(100)
	next := r.failedMax(key, slot)

	require.GreaterOrEqual(t, next, slot+maxRetrySlots)
	require.LessOrEqual(t, next, slot+maxRetrySlots+maxRetrySlots/2)
	require.False(t, r.due(key, next-1))
	require.True(t, r.due(key, next))

	// A later regular failure stays capped.
	require.LessOrEqual(t, r.failed(key, next), next+maxRetrySlots+maxRetrySlots/2)
	require.Equal(t, maxRetrySlots, r.delay[key])

	// A success resets the key.
	r.succeeded(key)
	require.True(t, r.due(key, 0))
}
