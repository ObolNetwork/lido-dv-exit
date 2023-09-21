// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bnapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	ethApi "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
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

// MockValidatorAPIForT returns a http.HandlerFunc that simulates a beacon node API for the
// validator state endpoint.
func MockValidatorAPIForT(_ *testing.T, validators map[string]ethApi.Validator) http.HandlerFunc {
	type retContainer struct {
		Data []*ethApi.Validator `json:"data"`
	}

	return func(writer http.ResponseWriter, request *http.Request) {
		vars := mux.Vars(request)

		valIDs := strings.Split(request.URL.Query().Get("id"), ",")
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
			_, _ = writer.Write(errBytes)
			return
		}

		var ret retContainer

		for _, valID := range valIDs {
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
				_, _ = writer.Write(errBytes)
				return
			}

			ret.Data = append(ret.Data, &valStatus)
		}

		if err := json.NewEncoder(writer).Encode(ret); err != nil {
			errBytes, err := json.Marshal(Error{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
			})

			if err != nil {
				panic(err) // fine here, it's a test
			}

			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = writer.Write(errBytes)
			return
		}
	}
}

func MockBeaconNodeForT(t *testing.T, validators map[string]ethApi.Validator) http.Handler {
	router := mux.NewRouter()

	router.HandleFunc("/eth/v1/beacon/genesis", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data struct {
				GenesisTime           string `json:"genesis_time"`
				GenesisValidatorsRoot string `json:"genesis_validators_root"`
				GenesisForkVersion    string `json:"genesis_fork_version"`
			} `json:"data"`
		}{
			Data: struct {
				GenesisTime           string `json:"genesis_time"`
				GenesisValidatorsRoot string `json:"genesis_validators_root"`
				GenesisForkVersion    string `json:"genesis_fork_version"`
			}{
				GenesisTime:           "1616508000",
				GenesisValidatorsRoot: "0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb",
				GenesisForkVersion:    "0x00001020",
			},
		})
	})

	router.HandleFunc("/eth/v1/config/spec", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data map[string]string `json:"data"`
		}{
			Data: map[string]string{
				"DOMAIN_VOLUNTARY_EXIT": "0x04000000",
			},
		})
	})

	router.HandleFunc("/eth/v1/config/deposit_contract", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data *ethApi.DepositContract `json:"data"`
		}{})
	})

	router.HandleFunc("/eth/v1/config/fork_schedule", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data []*phase0.Fork `json:"data"`
		}{
			Data: []*phase0.Fork{
				{
					PreviousVersion: phase0.Version{02, 00, 10, 20},
					CurrentVersion:  phase0.Version{03, 00, 10, 20},
					Epoch:           phase0.Epoch(162304),
				},
			},
		})
	})

	router.HandleFunc("/eth/v1/node/version", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data struct {
				Version string `json:"version"`
			} `json:"data"`
		}{})
	})

	router.HandleFunc("/eth/v1/beacon/states/{state_id}/validators", MockValidatorAPIForT(t, validators))

	return router
}
