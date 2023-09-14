package bnapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/obolnetwork/charon/app/errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	validatorStatePathTmpl = "/eth/v1/beacon/states/{state_id}/validators/{validator_id}"
	stateIDPath            = "{state_id}"
	valIDPath              = "{validator_id}"
)

// Error is the error struct that Beacon Node returns when HTTP status code is not 200.
type Error struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("http status %d: %s", e.Code, e.Message)
}

// StateID is the Ethereum beacon state identifier used during validator state queries.
type StateID int

const (
	StateIDHead StateID = iota
	StateIDGenesis
	StateIDFinalized
	StateIDJustified
	StateIDUnknown
)

func (s StateID) String() string {
	switch s {
	case StateIDHead:
		return "head"
	case StateIDGenesis:
		return "genesis"
	case StateIDFinalized:
		return "finalized"
	case StateIDJustified:
		return "justified"
	case StateIDUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// stringToStateID maps s to its StateID value.
// Will return StateIDUnknown if s doesn't map to any StateID value.
func stringToStateID(s string) StateID {
	switch s {
	case "head":
		return StateIDHead
	case "genesis":
		return StateIDGenesis
	case "finalized":
		return StateIDFinalized
	case "justified":
		return StateIDJustified
	default:
		return StateIDUnknown
	}
}

func pubkeyValid(pubKey string) error {
	if len(pubKey) < 98 { // BLS pubkey is 48 bytes, hex-encoded is 96, plus 0x == 98
		return errors.New("pubkey too short")
	}

	prefix := pubKey[:2]
	if prefix != "0x" {
		return errors.New("pubkey prefix is not 0x")
	}

	pubKey = pubKey[2:]

	if _, err := hex.DecodeString(pubKey); err != nil {
		return errors.Wrap(err, "pubkey not hex encoded")
	}

	return nil
}

func validatorStatePath(sid StateID, valPubkey string) (string, error) {
	if sid.String() == "unknown" {
		return "", errors.New("provided state id is unknown")
	}

	if err := pubkeyValid(valPubkey); err != nil {
		return "", errors.Wrap(err, "invalid pubkey")
	}

	r := strings.NewReplacer(
		stateIDPath,
		sid.String(),
		valIDPath,
		valPubkey,
	)

	return r.Replace(validatorStatePathTmpl), nil
}

type Client struct {
	BeaconNodeURL string
}

func (c Client) ValidatorStateForStateID(sid StateID, valPubkey string) (ValidatorState, error) {
	path, err := validatorStatePath(sid, valPubkey)
	if err != nil {
		return ValidatorState{}, err
	}

	u, err := url.ParseRequestURI(c.BeaconNodeURL)
	if err != nil {
		return ValidatorState{}, errors.Wrap(err, "invalid beacon node url")
	}

	u.Path = path

	resp, err := http.Get(u.String())
	if err != nil {
		return ValidatorState{}, errors.Wrap(err, "http get error")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var ret Error

		if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
			return ValidatorState{}, errors.Wrap(err, "json decoding error")
		}

		return ValidatorState{}, ret
	}

	var ret ValidatorState

	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return ValidatorState{}, errors.Wrap(err, "json decoding error")
	}

	return ret, nil
}

// MockValidatorAPIForT returns a http.HandlerFunc that simulates a beacon node API for the
// validator state endpoint.
func MockValidatorAPIForT(_ *testing.T, validators map[string]ValidatorState) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		vars := mux.Vars(request)

		valID := vars["validator_id"]
		rawStateID := vars["state_id"]

		stateID := stringToStateID(rawStateID)

		if stateID == StateIDUnknown {
			errBytes, err := json.Marshal(Error{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("Invalid state ID: %s", rawStateID),
			})

			if err != nil {
				panic(err) // fine here, it's a test
			}

			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(errBytes)
			return
		}

		valStatus, ok := validators[valID]

		if !ok {
			errBytes, err := json.Marshal(Error{
				Code:    http.StatusNotFound,
				Message: "Validator not found",
			})

			if err != nil {
				panic(err) // fine here, it's a test
			}

			writer.WriteHeader(http.StatusNotFound)
			writer.Write(errBytes)
			return
		}

		if err := json.NewEncoder(writer).Encode(valStatus); err != nil {
			errBytes, err := json.Marshal(Error{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
			})

			if err != nil {
				panic(err) // fine here, it's a test
			}

			writer.WriteHeader(http.StatusInternalServerError)
			writer.Write(errBytes)
			return
		}
	}
}
