// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	ethApi "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/handlers"
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

// Run runs beacon mock on the provided bind port.
func Run(_ context.Context, validators map[string]ethApi.Validator, bindAddr string) error {
	hf := MockBeaconNode(validators)

	return http.ListenAndServe(bindAddr, hf)
}

// MockValidatorAPI returns a http.HandlerFunc that simulates a beacon node API for the
// validator state endpoint.
func MockValidatorAPI(validators map[string]ethApi.Validator, workaroundLido bool) http.HandlerFunc {
	type retContainer struct {
		Data []*ethApi.Validator `json:"data"`
	}

	return func(writer http.ResponseWriter, request *http.Request) {
		vars := mux.Vars(request)

		var valIDs []string
		if val, ok := vars["valId"]; ok {
			valIDs = append(valIDs, val)
		} else {
			valIDs = strings.Split(request.URL.Query().Get("id"), ",")
		}

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

		var ret any

		if !workaroundLido {
			var container retContainer

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

				container.Data = append(container.Data, &valStatus)
			}

			ret = container
		} else {
			type container struct {
				Data *ethApi.Validator `json:"data"`
			}

			var c container

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

				c.Data = &valStatus
			}

			ret = c
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
		_, _ = writer.Write([]byte(
			`{"data":{"CONFIG_NAME":"mainnet","PRESET_BASE":"mainnet","TERMINAL_TOTAL_DIFFICULTY":"58750000000000000000000","TERMINAL_BLOCK_HASH":"0x0000000000000000000000000000000000000000000000000000000000000000","TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":"18446744073709551615","SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY":"128","MIN_GENESIS_ACTIVE_VALIDATOR_COUNT":"16384","MIN_GENESIS_TIME":"1606824000","GENESIS_FORK_VERSION":"0x00000000","GENESIS_DELAY":"604800","ALTAIR_FORK_VERSION":"0x01000000","ALTAIR_FORK_EPOCH":"74240","BELLATRIX_FORK_VERSION":"0x02000000","BELLATRIX_FORK_EPOCH":"144896","CAPELLA_FORK_VERSION":"0x03000000","CAPELLA_FORK_EPOCH":"194048","SECONDS_PER_SLOT":"12","SECONDS_PER_ETH1_BLOCK":"14","MIN_VALIDATOR_WITHDRAWABILITY_DELAY":"256","SHARD_COMMITTEE_PERIOD":"256","ETH1_FOLLOW_DISTANCE":"2048","SUBNETS_PER_NODE":"2","INACTIVITY_SCORE_BIAS":"4","INACTIVITY_SCORE_RECOVERY_RATE":"16","EJECTION_BALANCE":"16000000000","MIN_PER_EPOCH_CHURN_LIMIT":"4","CHURN_LIMIT_QUOTIENT":"65536","PROPOSER_SCORE_BOOST":"40","DEPOSIT_CHAIN_ID":"1","DEPOSIT_NETWORK_ID":"1","DEPOSIT_CONTRACT_ADDRESS":"0x00000000219ab540356cbb839cbe05303d7705fa","GOSSIP_MAX_SIZE":"10485760","MIN_EPOCHS_FOR_BLOCK_REQUESTS":"33024","MAX_CHUNK_SIZE":"10485760","TTFB_TIMEOUT":"5","RESP_TIMEOUT":"10","MESSAGE_DOMAIN_INVALID_SNAPPY":"0x00000000","MESSAGE_DOMAIN_VALID_SNAPPY":"0x01000000","ATTESTATION_SUBNET_EXTRA_BITS":"0","ATTESTATION_SUBNET_PREFIX_BITS":"6","MAX_COMMITTEES_PER_SLOT":"64","TARGET_COMMITTEE_SIZE":"128","MAX_VALIDATORS_PER_COMMITTEE":"2048","SHUFFLE_ROUND_COUNT":"90","HYSTERESIS_QUOTIENT":"4","HYSTERESIS_DOWNWARD_MULTIPLIER":"1","HYSTERESIS_UPWARD_MULTIPLIER":"5","SAFE_SLOTS_TO_UPDATE_JUSTIFIED":"8","MIN_DEPOSIT_AMOUNT":"1000000000","MAX_EFFECTIVE_BALANCE":"32000000000","EFFECTIVE_BALANCE_INCREMENT":"1000000000","MIN_ATTESTATION_INCLUSION_DELAY":"1","SLOTS_PER_EPOCH":"32","MIN_SEED_LOOKAHEAD":"1","MAX_SEED_LOOKAHEAD":"4","EPOCHS_PER_ETH1_VOTING_PERIOD":"64","SLOTS_PER_HISTORICAL_ROOT":"8192","MIN_EPOCHS_TO_INACTIVITY_PENALTY":"4","EPOCHS_PER_HISTORICAL_VECTOR":"65536","EPOCHS_PER_SLASHINGS_VECTOR":"8192","HISTORICAL_ROOTS_LIMIT":"16777216","VALIDATOR_REGISTRY_LIMIT":"1099511627776","BASE_REWARD_FACTOR":"64","WHISTLEBLOWER_REWARD_QUOTIENT":"512","PROPOSER_REWARD_QUOTIENT":"8","INACTIVITY_PENALTY_QUOTIENT":"67108864","MIN_SLASHING_PENALTY_QUOTIENT":"128","PROPORTIONAL_SLASHING_MULTIPLIER":"1","MAX_PROPOSER_SLASHINGS":"16","MAX_ATTESTER_SLASHINGS":"2","MAX_ATTESTATIONS":"128","MAX_DEPOSITS":"16","MAX_VOLUNTARY_EXITS":"16","INACTIVITY_PENALTY_QUOTIENT_ALTAIR":"50331648","MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR":"64","PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR":"2","SYNC_COMMITTEE_SIZE":"512","EPOCHS_PER_SYNC_COMMITTEE_PERIOD":"256","MIN_SYNC_COMMITTEE_PARTICIPANTS":"1","INACTIVITY_PENALTY_QUOTIENT_BELLATRIX":"16777216","MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX":"32","PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX":"3","MAX_BYTES_PER_TRANSACTION":"1073741824","MAX_TRANSACTIONS_PER_PAYLOAD":"1048576","BYTES_PER_LOGS_BLOOM":"256","MAX_EXTRA_DATA_BYTES":"32","MAX_BLS_TO_EXECUTION_CHANGES":"16","MAX_WITHDRAWALS_PER_PAYLOAD":"16","MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP":"16384","DOMAIN_VOLUNTARY_EXIT":"0x04000000","DOMAIN_DEPOSIT":"0x03000000","DOMAIN_AGGREGATE_AND_PROOF":"0x06000000","DOMAIN_BEACON_PROPOSER":"0x00000000","TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE":"16","TARGET_AGGREGATORS_PER_COMMITTEE":"16","DOMAIN_SELECTION_PROOF":"0x05000000","DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF":"0x08000000","BLS_WITHDRAWAL_PREFIX":"0x00","DOMAIN_CONTRIBUTION_AND_PROOF":"0x09000000","SYNC_COMMITTEE_SUBNET_COUNT":"4","DOMAIN_BEACON_ATTESTER":"0x01000000","DOMAIN_RANDAO":"0x02000000","DOMAIN_APPLICATION_MASK":"0x00000001","DOMAIN_SYNC_COMMITTEE":"0x07000000"}}`,
		))
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

	router.Handle("/eth/v1/beacon/pool/voluntary_exits", logHandler(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))

	router.Handle("/eth/v1/beacon/states/{state_id}/validators", logHandler(MockValidatorAPI(validators, false)))
	router.Handle("/eth/v1/beacon/states/{state_id}/validators/{valId}", logHandler(MockValidatorAPI(validators, true)))

	return router
}
