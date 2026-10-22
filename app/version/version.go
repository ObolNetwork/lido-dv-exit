// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package version provides the lido-dv-exit version, as charon's app/version does.
package version

import (
	"fmt"
	"runtime/debug"
)

// version is a string since it is overwritten at build time with the git tag for releases:
// -ldflags=-X github.com/ObolNetwork/lido-dv-exit/app/version.version=<tag>.
//   - Main branch: v0.X-dev
//   - Releases: the git tag, e.g. v0.5.3
var version = "v0.6-dev"

// unknown is the git commit and time of a binary built without VCS information.
const unknown = "unknown"

// Version returns the version of the binary.
func Version() string {
	return version
}

// GitCommit returns the short git commit hash and commit timestamp from the build info.
func GitCommit() (hash string, timestamp string) {
	hash, timestamp = unknown, unknown

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return hash, timestamp
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			hash = s.Value[:min(len(s.Value), 7)]
		case "vcs.time":
			timestamp = s.Value
		default:
		}
	}

	return hash, timestamp
}

// String returns the version and git commit hash, e.g. "v0.5.3 [git_commit_hash=1a2b3c4]".
func String() string {
	hash, _ := GitCommit()

	return fmt.Sprintf("%s [git_commit_hash=%s]", version, hash)
}
