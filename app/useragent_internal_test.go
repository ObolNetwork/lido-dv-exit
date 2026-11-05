// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserAgentTransport(t *testing.T) {
	var got []string

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("User-Agent"))
	}))
	defer srv.Close()

	cl := &http.Client{Transport: userAgentTransport{next: http.DefaultTransport, ua: UserAgent()}}

	// A request without a User-Agent gets lido-dv-exit's.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	res, err := cl.Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	// One that sets its own keeps it.
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "custom/v1")

	res, err = cl.Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	require.Equal(t, []string{UserAgent(), "custom/v1"}, got)
	require.True(t, strings.HasPrefix(UserAgent(), "lido-dv-exit/"))
}
