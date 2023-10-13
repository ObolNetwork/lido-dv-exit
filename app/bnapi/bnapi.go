// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bnapi

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ethApi "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

//go:embed mainnet_spec.json
var mainnetJSONSpec []byte

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

// Run runs beacon mock on the provided bind port.
func Run(_ context.Context, validators map[string]ethApi.Validator, bindAddr string) error {
	hf := MockBeaconNode(validators)

	return http.ListenAndServe(bindAddr, hf)
}

// MockBeaconNode returns a beacon node http.Handler mock with the provided validator map.
func MockBeaconNode(validators map[string]ethApi.Validator) http.Handler {
	router := mux.NewRouter()

	var slot atomic.Uint64
	slot.Store(7423039)

	go func() {
		t := time.NewTicker(1 * time.Second)

		for range t.C {
			slot.Add(1)
		}
	}()

	for _, validator := range validators {
		validators[strconv.FormatUint(uint64(validator.Index), 10)] = validator
	}

	logHandler := func(h http.HandlerFunc) http.Handler {
		return handlers.LoggingHandler(os.Stdout, h)
	}

	router.NotFoundHandler = logHandler(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	})

	router.Handle("/eth/v1/node/syncing", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		s := strconv.FormatUint(slot.Load(), 10)
		data := map[string]any{
			"data": map[string]any{
				"head_slot":     s,
				"sync_distance": "1",
				"is_syncing":    false,
				"is_optimistic": false,
			},
		}
		_ = json.NewEncoder(writer).Encode(data)
	}))

	router.Handle("/eth/v1/beacon/genesis", logHandler(func(writer http.ResponseWriter, request *http.Request) {
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
				GenesisTime:           "1606824023",
				GenesisValidatorsRoot: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
				GenesisForkVersion:    "0x00000000",
			},
		})
	}))

	router.Handle("/eth/v1/config/spec", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		// Too much to be a responsible human being
		_, _ = writer.Write(mainnetJSONSpec)
	}))

	router.Handle("/eth/v1/config/deposit_contract", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data *ethApi.DepositContract `json:"data"`
		}{})
	}))

	router.Handle("/eth/v1/config/fork_schedule", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data []*phase0.Fork `json:"data"`
		}{
			Data: []*phase0.Fork{
				{
					PreviousVersion: phase0.Version{00, 00, 00, 00},
					CurrentVersion:  phase0.Version{00, 00, 00, 00},
					Epoch:           phase0.Epoch(0),
				},
				{
					PreviousVersion: phase0.Version{00, 00, 00, 00},
					CurrentVersion:  phase0.Version{01, 00, 00, 00},
					Epoch:           phase0.Epoch(74240),
				},
				{
					PreviousVersion: phase0.Version{01, 00, 00, 00},
					CurrentVersion:  phase0.Version{02, 00, 00, 00},
					Epoch:           phase0.Epoch(144896),
				},
				{
					PreviousVersion: phase0.Version{02, 00, 00, 00},
					CurrentVersion:  phase0.Version{03, 00, 00, 00},
					Epoch:           phase0.Epoch(194048),
				},
			},
		})
	}))

	router.Handle("/eth/v1/beacon/states/{state_id}/fork", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data      *phase0.Fork `json:"data"`
			Finalized bool         `json:"finalized"`
		}{
			Finalized: true,
			Data: &phase0.Fork{
				PreviousVersion: phase0.Version{02, 00, 00, 00},
				CurrentVersion:  phase0.Version{03, 00, 00, 00},
				Epoch:           phase0.Epoch(194048),
			},
		})
	}))

	router.Handle("/eth/v1/node/version", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data struct {
				Version string `json:"version"`
			} `json:"data"`
		}{})
	}))

	vsh := validatorStateHandler{
		lock:       sync.Mutex{},
		validators: validators,
	}

	router.Handle("/eth/v1/beacon/pool/voluntary_exits", logHandler(vsh.exitValidator(&slot)))

	router.Handle("/eth/v1/beacon/states/{state_id}/validators", logHandler(vsh.getValidator(false)))
	router.Handle("/eth/v1/beacon/states/{state_id}/validators/{valId}", logHandler(vsh.getValidator(true)))

	return router
}

type getValidatorsResponse struct {
	Data []*ethApi.Validator `json:"data"`
}

type getValidatorResponse struct {
	Data *ethApi.Validator `json:"data"`
}

type validatorStateHandler struct {
	lock       sync.Mutex
	validators map[string]ethApi.Validator
}

func (vsh *validatorStateHandler) exitValidator(slotCounter *atomic.Uint64) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		vsh.lock.Lock()
		defer vsh.lock.Unlock()

		var exitMsg phase0.SignedVoluntaryExit

		if err := json.NewDecoder(request.Body).Decode(&exitMsg); err != nil {
			errBytes, err := json.Marshal(Error{
				Code:    http.StatusBadRequest,
				Message: "Bad Request",
			})

			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write(errBytes)
		}

		vIdxStr := strconv.FormatUint(uint64(exitMsg.Message.ValidatorIndex), 10)
		validator, ok := vsh.validators[vIdxStr]
		if !ok {
			validatorNotFound(writer)
			return
		}

		validator.Validator.ExitEpoch = phase0.Epoch(slotCounter.Load() + 10000) // exit in 10000 slots

		validator.Status = ethApi.ValidatorStateActiveExiting

		vsh.validators[vIdxStr] = validator

		writer.WriteHeader(http.StatusOK)
	}
}

func (vsh *validatorStateHandler) getValidator(singleValidatorQuery bool) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		vsh.lock.Lock()
		defer vsh.lock.Unlock()

		vars := mux.Vars(request)

		var valIDs []string

		if singleValidatorQuery {
			val, ok := vars["valId"]
			if !ok {
				validatorNotFound(writer)
				return
			}

			valIDs = append(valIDs, val)
		} else {
			valIDs = request.URL.Query()["id"]
			if len(valIDs) == 0 {
				validatorNotFound(writer)
				return
			}
		}

		rawStateID := vars["state_id"]

		stateID := stringToStateID(rawStateID)

		if stateID == StateIDUnknown {
			errBytes, err := json.Marshal(Error{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("Invalid state ID: %s", rawStateID),
			})

			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write(errBytes)
			return
		}

		var ret any

		if !singleValidatorQuery {
			var container getValidatorsResponse

			for _, valID := range valIDs {
				valStatus, ok := vsh.validators[valID]

				if !ok {
					validatorNotFound(writer)
					return
				}

				container.Data = append(container.Data, &valStatus)
			}

			ret = container
		} else {
			var c getValidatorResponse

			valStatus, ok := vsh.validators[valIDs[0]] // guaranteed by the router to have at least one element

			if !ok {
				validatorNotFound(writer)
				return
			}

			c.Data = &valStatus

			ret = c
		}

		if err := json.NewEncoder(writer).Encode(ret); err != nil {
			errBytes, _ := json.Marshal(Error{ // ignoring error here since we'll write 500 regardless
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
			})

			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = writer.Write(errBytes)
			return
		}
	}
}

func validatorNotFound(writer http.ResponseWriter) {
	errBytes, err := json.Marshal(Error{
		Code:    http.StatusNotFound,
		Message: "Validator not found",
	})

	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusNotFound)
	_, _ = writer.Write(errBytes)
}
