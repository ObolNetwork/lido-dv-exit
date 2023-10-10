// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	partialExitTmpl = "/exp/partial_exits/{lockhash}"
	fullExitTmpl    = "/exp/exit/{validator_pubkey}"
	lockHashPath    = "{lockhash}"
	valPubkeyPath   = "{validator_pubkey}"
)

var ErrNoExit = errors.New("no exit for the given validator puiblic key")

func partialExitURL(lockHash string) string {
	return strings.NewReplacer(
		lockHashPath,
		lockHash,
	).Replace(partialExitTmpl)
}

func bearerString(token string) string {
	return fmt.Sprintf("Bearer %s", token)
}

// TODO(gsora): validate public key
func fullExitURL(valPubkey string) string {
	return strings.NewReplacer(
		valPubkeyPath,
		valPubkey,
	).Replace(fullExitTmpl)
}

// PartialExits is an array of ExitMessage that have been signed with a partial key.
type PartialExits []ExitBlob

// ExitBlob is an exit message alongside its BLS12-381 hex-encoded signature.
type ExitBlob struct {
	PublicKey         string                     `json:"public_key,omitempty"`
	SignedExitMessage eth2p0.SignedVoluntaryExit `json:"signed_exit_message"`
	ShareIdx          int                        `json:"share_idx,omitempty"`
}

// FullExitResponse contains all partial signatures, epoch and validator index to construct a full exit message for
// a validator.
// Signatures are ordered by share index.
type FullExitResponse struct {
	Epoch          string                `json:"epoch"`
	ValidatorIndex eth2p0.ValidatorIndex `json:"validator_index"`
	Signatures     []string              `json:"signatures"`
}

type Client struct {
	ObolAPIUrl string
}

// PostPartialExit POSTs the set of msg's to the Obol API, for a given lock hash.
func (c Client) PostPartialExit(ctx context.Context, lockHash string, authToken string, msg ...ExitBlob) error {
	path := partialExitURL(lockHash)

	u, err := url.ParseRequestURI(c.ObolAPIUrl)
	if err != nil {
		return errors.Wrap(err, "bad obol api url")
	}

	u.Path = path

	data, err := json.Marshal(PartialExits(msg))
	if err != nil {
		return errors.Wrap(err, "json marshal error")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return errors.Wrap(err, "http new post request")
	}

	req.Header.Set("Authorization", bearerString(authToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "http post error")
	}

	if resp.StatusCode != http.StatusCreated {
		return errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	return nil
}

// GetFullExit gets the full exit message for a given validator public key.
func (c Client) GetFullExit(ctx context.Context, valPubkey string, authToken string) (ExitBlob, error) {
	path := fullExitURL(valPubkey)

	u, err := url.ParseRequestURI(c.ObolAPIUrl)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "bad obol api url")
	}

	u.Path = path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "http new get request")
	}

	req.Header.Set("Authorization", bearerString(authToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "http get error")
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return ExitBlob{}, ErrNoExit
		}
		return ExitBlob{}, errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	var er FullExitResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return ExitBlob{}, errors.Wrap(err, "json unmarshal error")
	}

	// do aggregation and cache exit
	rawSignatures := make(map[int]tbls.Signature)

	for sigIdx, sigStr := range er.Signatures {
		if len(sigStr) < 2 {
			return ExitBlob{}, errors.New("signature string has invalid size", z.Int("size", len(sigStr)))
		}

		sigBytes, err := hex.DecodeString(sigStr[2:])
		if err != nil {
			return ExitBlob{}, errors.Wrap(err, "partial signature unmarshal")
		}

		sig, err := tblsconv.SignatureFromBytes(sigBytes)
		if err != nil {
			return ExitBlob{}, errors.Wrap(err, "invalid partial signature")
		}

		rawSignatures[sigIdx+1] = sig
	}

	fullSig, err := tbls.ThresholdAggregate(rawSignatures)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "partial signatures threshold aggregate")
	}

	epochUint64, err := strconv.ParseUint(er.Epoch, 10, 64)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "epoch parsing")
	}

	return ExitBlob{
		PublicKey: valPubkey,
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message: &eth2p0.VoluntaryExit{
				Epoch:          eth2p0.Epoch(epochUint64),
				ValidatorIndex: er.ValidatorIndex,
			},
			Signature: eth2p0.BLSSignature(fullSig),
		},
	}, nil
}
