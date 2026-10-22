// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/version"
)

func TestVersion(t *testing.T) {
	// The default branch version and release tags are both v-prefixed semver-ish strings.
	require.Regexp(t, `^v\d+\.\d+(\.\d+)?(-[0-9A-Za-z.]+)?$`, version.Version())

	hash, timestamp := version.GitCommit()
	require.NotEmpty(t, hash)
	require.NotEmpty(t, timestamp)
	require.LessOrEqual(t, len(hash), 7)

	require.Regexp(t, `^v\S+ \[git_commit_hash=\S+\]$`, version.String())
}
