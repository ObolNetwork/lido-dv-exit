// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bnapi

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/obolnetwork/charon/app/errors"

	"github.com/ObolNetwork/lido-dv-exit/app/util"
)

//go:embed mainnet_spec.json
var mainnetJSONSpec []byte

var capellaForkMap = map[string]string{
	"0x00000000": "0x03000000",
	"0x00001020": "0x03001020",
	"0x00000064": "0x03000064",
	"0x90000069": "0x90000072",
	"0x01017000": "0x04017000",
	"0x10000910": "0x40000910",
}

// CapellaFork maps generic fork hashes to their specific Capella hardfork
// values.
func CapellaFork(forkHash string) (string, error) {
	d, ok := capellaForkMap[forkHash]
	if !ok {
		return "", errors.New("no capella for specified fork")
	}

	return d, nil
}

type forkDataType struct {
	CurrentVersion        [4]byte
	GenesisValidatorsRoot [32]byte
}

func (e forkDataType) GetTree() (*ssz.Node, error) {
	node, err := ssz.ProofTree(e)
	if err != nil {
		return nil, errors.Wrap(err, "proof tree")
	}

	return node, nil
}

func (e forkDataType) HashTreeRoot() ([32]byte, error) {
	hash, err := ssz.HashWithDefaultHasher(e)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash with default hasher")
	}

	return hash, nil
}

func (e forkDataType) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'CurrentVersion'
	hh.PutBytes(e.CurrentVersion[:])

	// Field (1) 'GenesisValidatorsRoot'
	hh.PutBytes(e.GenesisValidatorsRoot[:])

	hh.Merkleize(indx)

	return nil
}

// ComputeDomain computes the domain for a given domainType, genesisValidatorRoot at the specified fork hash.
func ComputeDomain(forkHash string, domainType eth2p0.DomainType, genesisValidatorRoot eth2p0.Root) (eth2p0.Domain, error) {
	fb, err := util.ForkHashToBytes(forkHash)
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "fork hash hex")
	}

	rawFdt := forkDataType{GenesisValidatorsRoot: genesisValidatorRoot, CurrentVersion: [4]byte(fb)}
	fdt, err := rawFdt.HashTreeRoot()
	if err != nil {
		return eth2p0.Domain{}, errors.Wrap(err, "fork data type hash tree root")
	}

	var domain []byte
	domain = append(domain, domainType[:]...)
	domain = append(domain, fdt[:28]...)

	return eth2p0.Domain(domain), nil
}

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
func Run(_ context.Context, validators map[string]eth2v1.Validator, bindAddr string) error {
	hf := MockBeaconNode(validators)

	srv := http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           hf,
		Addr:              bindAddr,
	}

	if err := srv.ListenAndServe(); err != nil {
		return errors.Wrap(err, "beacon node mock error")
	}

	return nil
}

// MockBeaconNode returns a beacon node http.Handler mock with the provided validator map.
func MockBeaconNode(validators map[string]eth2v1.Validator) http.Handler {
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
		addressBytes, err := hex.DecodeString("07b39f4fde4a38bace212b546dac87c58dfe3fdc")
		if err != nil {
			panic("cannot decode static deposit contract address, impossible!")
		}

		_ = json.NewEncoder(writer).Encode(struct {
			Data *eth2v1.DepositContract `json:"data"`
		}{
			Data: &eth2v1.DepositContract{
				ChainID: 0x000000,
				Address: addressBytes,
			},
		})
	}))

	router.Handle("/eth/v1/config/fork_schedule", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data []*eth2p0.Fork `json:"data"`
		}{
			Data: []*eth2p0.Fork{
				{
					PreviousVersion: eth2p0.Version{0o0, 0o0, 0o0, 0o0},
					CurrentVersion:  eth2p0.Version{0o0, 0o0, 0o0, 0o0},
					Epoch:           eth2p0.Epoch(0),
				},
				{
					PreviousVersion: eth2p0.Version{0o0, 0o0, 0o0, 0o0},
					CurrentVersion:  eth2p0.Version{0o1, 0o0, 0o0, 0o0},
					Epoch:           eth2p0.Epoch(74240),
				},
				{
					PreviousVersion: eth2p0.Version{0o1, 0o0, 0o0, 0o0},
					CurrentVersion:  eth2p0.Version{0o2, 0o0, 0o0, 0o0},
					Epoch:           eth2p0.Epoch(144896),
				},
				{
					PreviousVersion: eth2p0.Version{0o2, 0o0, 0o0, 0o0},
					CurrentVersion:  eth2p0.Version{0o3, 0o0, 0o0, 0o0},
					Epoch:           eth2p0.Epoch(194048),
				},
			},
		})
	}))

	router.Handle("/eth/v1/beacon/states/{state_id}/fork", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(struct {
			Data      *eth2p0.Fork `json:"data"`
			Finalized bool         `json:"finalized"`
		}{
			Finalized: true,
			Data: &eth2p0.Fork{
				PreviousVersion: eth2p0.Version{0o2, 0o0, 0o0, 0o0},
				CurrentVersion:  eth2p0.Version{0o3, 0o0, 0o0, 0o0},
				Epoch:           eth2p0.Epoch(194048),
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
	Data []*eth2v1.Validator `json:"data"`
}

type getValidatorResponse struct {
	Data *eth2v1.Validator `json:"data"`
}

type validatorStateHandler struct {
	lock       sync.Mutex
	validators map[string]eth2v1.Validator
}

func (vsh *validatorStateHandler) exitValidator(slotCounter *atomic.Uint64) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		vsh.lock.Lock()
		defer vsh.lock.Unlock()

		var exitMsg eth2p0.SignedVoluntaryExit

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

		validator.Validator.ExitEpoch = eth2p0.Epoch(slotCounter.Load() + 10000) // exit in 10000 slots

		validator.Status = eth2v1.ValidatorStateActiveExiting

		vsh.validators[vIdxStr] = validator

		writer.WriteHeader(http.StatusOK)
	}
}

type validatorsBody struct {
	IDs      []string `json:"ids,omitempty"`
	Statuses []string `json:"statuses,omitempty"`
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
				writer.WriteHeader(http.StatusBadRequest)
				return
			}

			valIDs = append(valIDs, val)
		} else {
			if request.Method == http.MethodGet {
				valIDs = request.URL.Query()["id"]
			} else if request.Method == http.MethodPost {
				var valBody validatorsBody
				err := json.NewDecoder(request.Body).Decode(&valBody)
				if err != nil {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				valIDs = valBody.IDs
			} else {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}

			if len(valIDs) == 0 {
				validatorNotFound(writer)
				return
			}

			if len(valIDs) == 1 && strings.Contains(valIDs[0], ",") { // also handle comma-separated validator IDs
				commaSeparated := valIDs[0]

				valIDs = strings.Split(commaSeparated, ",")
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
