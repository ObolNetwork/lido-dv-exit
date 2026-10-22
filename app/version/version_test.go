// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	// The default branch version and release tags are both v-prefixed semver-ish strings.
	require.Regexp(t, regexp.MustCompile(`^v\d+\.\d+(\.\d+)?(-[0-9A-Za-z.]+)?$`), Version())

	hash, timestamp := GitCommit()
	require.NotEmpty(t, hash)
	require.NotEmpty(t, timestamp)
	require.LessOrEqual(t, len(hash), 7)

	require.Regexp(t, regexp.MustCompile(`^v\S+ \[git_commit_hash=\S+\]$`), String())
}
