// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"net/http"
	"runtime/debug"

	"github.com/ObolNetwork/lido-dv-exit/app/version"
)

// charonModule is the module path of charon, whose obolapi client lido-dv-exit uses.
const charonModule = "github.com/obolnetwork/charon"

// UserAgent returns the User-Agent lido-dv-exit sends to the Obol API, e.g.
// "lido-dv-exit/v0.7.0 charon/v1.11.2", so the API can attribute its traffic.
func UserAgent() string {
	ua := "lido-dv-exit/" + version.Version()

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ua
	}

	for _, dep := range info.Deps {
		if dep.Path == charonModule {
			return ua + " charon/" + dep.Version
		}
	}

	return ua
}

// SetDefaultUserAgent makes requests sent through http.DefaultTransport without a User-Agent
// carry UserAgent() instead of Go's "Go-http-client/1.1". charon v1.11.2's obolapi client uses
// http.DefaultTransport and has no User-Agent option.
//
// TODO: pass obolapi.WithUserAgent("lido-dv-exit/"+version.Version()) to obolapi.New and drop
// this once charon is bumped to a release that has it.
func SetDefaultUserAgent() {
	http.DefaultTransport = userAgentTransport{
		next: http.DefaultTransport,
		ua:   UserAgent(),
	}
}

// userAgentTransport sets the User-Agent header of requests that don't have one.
type userAgentTransport struct {
	next http.RoundTripper
	ua   string
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") != "" {
		return t.next.RoundTrip(req)
	}

	// RoundTrippers must not modify the request, so set the header on a clone.
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.ua)

	return t.next.RoundTrip(req)
}
