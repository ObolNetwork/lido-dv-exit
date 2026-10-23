// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:revive
package util

import (
	"encoding/hex"
	"runtime/debug"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// validatorPubkBytesLen is the amount of bytes a well-formed validator public key must contain.
	validatorPubkBytesLen = 48

	// forkHashLen is the amount of bytes a well-formed Ethereum fork hash must contain.
	forkHashLen = 4
)

// from0x decodes hex-encoded data and expects it to be exactly of len(length).
// Accepts both 0x-prefixed strings or not.
func from0x(data string, length int) ([]byte, error) {
	if data == "" {
		return nil, errors.New("empty data")
	}

	b, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	} else if len(b) != length {
		return nil, errors.New(
			"invalid hex length",
			z.Int("expect", length),
			z.Int("actual", len(b)),
		)
	}

	return b, nil
}

// ForkHashToBytes returns the bytes representation of the Ethereum fork hash string passed in input.
// If forkHAsh is empty, contains badly-formatted hex data or doesn't yield exactly 4 bytes, this function will error.
func ForkHashToBytes(forkHash string) ([]byte, error) {
	return from0x(forkHash, forkHashLen)
}

// ValidatorPubkeyToBytes returns the bytes representation of the validator hex-encoded public key string passed in input.
// If pubkey is empty, contains badly-formatted hex data or doesn't yield exactly 48 bytes, this function will error.
func ValidatorPubkeyToBytes(pubkey string) ([]byte, error) {
	return from0x(pubkey, validatorPubkBytesLen)
}

// VCSInfoMap gets vcs information from bi and returns them as a map[string]string.
func VCSInfoMap(bi *debug.BuildInfo) map[string]string {
	ret := map[string]string{
		"vcs.revision": "",
		"vcs.time":     "",
		"vcs.modified": "",
	}

	if bi == nil {
		return ret
	}

	for _, element := range bi.Settings {
		if _, ok := ret[element.Key]; ok {
			ret[element.Key] = element.Value
		}
	}

	return ret
}

// GitHash returns the git hash of the binary at the moment it was compiled.
func GitHash() string {
	raw, _ := debug.ReadBuildInfo()

	info := VCSInfoMap(raw)

	return info["vcs.revision"]
}
