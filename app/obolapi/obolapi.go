package obolapi

import (
	"bytes"
	"encoding/json"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"net/http"
	"net/url"
	"strings"
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

type Client struct {
	ObolAPIUrl string
}

// PostPartialExit POSTs the set of msg's to the Obol API, for a given lock hash.
func (c Client) PostPartialExit(lockHash string, msg ...ExitBlob) error {
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

	resp, err := http.Post(u.String(), "application/json", bytes.NewReader(data))
	if err != nil {
		return errors.Wrap(err, "http post error")
	}

	if resp.StatusCode != 200 {
		return errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	return nil
}

// GetFullExit gets the full exit message for a given validator public key.
func (c Client) GetFullExit(valPubkey string) (ExitBlob, error) {
	path := fullExitURL(valPubkey)

	u, err := url.ParseRequestURI(c.ObolAPIUrl)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "bad obol api url")
	}

	u.Path = path

	resp, err := http.Get(u.String())
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "http get error")
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return ExitBlob{}, ErrNoExit
		}
		return ExitBlob{}, errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	defer resp.Body.Close()

	var ret ExitBlob
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return ExitBlob{}, errors.Wrap(err, "json unmarshal error")
	}

	return ret, nil
}
