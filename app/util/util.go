// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package util

import (
	"encoding/hex"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	// validatorPubkBytesLen is the amount of bytes a well-formed validator public key must contain.
	validatorPubkBytesLen = 48

	// signatureBytesLen is the amount of bytes a well-formed validator signature must contain.
	signatureBytesLen = 96
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
		return nil, errors.Wrap(err,
			"invalid hex length",
			z.Int("expect", length),
			z.Int("actual", len(b)),
		)
	}

	return b, nil
}

// ValidatorPubkeyToBytes returns the bytes representation of the validator hex-encoded public key string passed in input.
// If pubkey is empty, contains badly-formatted hex data or doesn't yield exactly 48 bytes, this function will error.
func ValidatorPubkeyToBytes(pubkey string) ([]byte, error) {
	return from0x(pubkey, validatorPubkBytesLen)
}

// SignatureToBytes returns the bytes representation of the hex-encoded signature string passed in input.
// If signature is empty, contains badly-formatted hex data or doesn't yield exactly 96 bytes, this function will error.
func SignatureToBytes(signature string) ([]byte, error) {
	return from0x(signature, signatureBytesLen)
}
