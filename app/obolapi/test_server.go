// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type contextKey string

const (
	tokenContextKey contextKey = "token"
)

type tsError struct {
	Message string
}

func writeErr(wr http.ResponseWriter, status int, msg string) {
	resp, err := json.Marshal(tsError{Message: msg})
	if err != nil {
		panic(err) // never happens
	}

	wr.WriteHeader(status)
	_, _ = wr.Write(resp)
}

// testServer is a mock implementation (but that actually does cryptography) of the Obol API side,
// which will handle storing and recollecting partial signatures.
type testServer struct {
	// for convenience, this thing handles one request at a time
	lock sync.Mutex

	// store the partial exits by the validator pubkey
	partialExits map[string]PartialExits

	// store the lock file by its lock hash
	lockFiles map[string]cluster.Lock

	// store the completed exits by the validator pubkey
	fullExits map[string]ExitBlob

	// store for each validator, a set of tokens which are authorized to retrieve a given full exit message
	// the token is a base64-encoded string
	authTokens map[string]map[string]bool
}

// addLockFiles adds a set of lock files to ts.
func (ts *testServer) addLockFiles(lock cluster.Lock) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	ts.lockFiles["0x"+hex.EncodeToString(lock.LockHash)] = lock
}

func (ts *testServer) HandlePartialExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).(string)
	if !ok {
		log.Error(request.Context(), "received context without token, that's impossible!", nil)
		return
	}

	vars := mux.Vars(request)

	var data PartialExits

	if err := json.NewDecoder(request.Body).Decode(&data); err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid body")
		return
	}

	lockHash := vars["lockhash"]
	if lockHash == "" {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
	}

	for _, exit := range data {
		exit := exit
		valFound := false

		for _, lockVal := range lock.Validators {
			if strings.EqualFold(exit.PublicKey, lockVal.PublicKeyHex()) {
				valFound = true
				break
			}
		}

		if !valFound {
			continue
		}

		// check if there's a full exit already, if yes, continue
		if _, ok := ts.fullExits[exit.PublicKey]; ok {
			continue
		}

		// check that the last partial exit's data is the same as the new one
		if len(ts.partialExits[exit.PublicKey]) > 0 && !ts.partialExitsMatch(exit) {
			writeErr(writer, http.StatusBadRequest, "wrong partial exit for the selected validator")
			return
		}

		if len(ts.partialExits[exit.PublicKey])+1 > len(lock.Operators) { // we're already at threshold
			writeErr(writer, http.StatusBadRequest, "already at threshold for selected validator")
			return
		}

		ts.partialExits[exit.PublicKey] = append(ts.partialExits[exit.PublicKey], exit)

		am, ok := ts.authTokens[exit.PublicKey]
		if !ok {
			ts.authTokens[exit.PublicKey] = map[string]bool{}
			am = ts.authTokens[exit.PublicKey]
		}

		am[authToken] = true

		if len(ts.partialExits[exit.PublicKey]) == len(lock.Operators) {
			// do aggregation and cache exit
			rawSignatures := make(map[int]tbls.Signature)

			for _, pe := range ts.partialExits[exit.PublicKey] {
				sig, err := tblsconv.SignatureFromBytes(pe.SignedExitMessage.Signature[:])
				if err != nil {
					writeErr(writer, http.StatusInternalServerError, "found partial exit with invalid signature bytes")
					return
				}

				rawSignatures[pe.ShareIdx] = sig
			}

			fullSig, err := tbls.ThresholdAggregate(rawSignatures)
			if err != nil {
				writeErr(writer, http.StatusInternalServerError, errors.Wrap(err, "could not aggregate full signature").Error())
				return
			}

			exit.SignedExitMessage.Signature = eth2p0.BLSSignature(fullSig)

			ts.fullExits[exit.PublicKey] = ExitBlob{
				PublicKey:         exit.PublicKey,
				SignedExitMessage: exit.SignedExitMessage,
			}
		}
	}
}

func (ts *testServer) HandleFullExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).(string)
	if !ok {
		log.Error(request.Context(), "received context without token, that's impossible!", nil)
		return
	}

	vars := mux.Vars(request)

	valPubkey := vars["validator_pubkey"]

	am, ok := ts.authTokens[valPubkey]
	if !ok {
		writeErr(writer, http.StatusUnauthorized, "no validator associated with auth token")
		return
	}

	if _, ok := am[authToken]; !ok {
		writeErr(writer, http.StatusUnauthorized, "auth token for validator refused")
		return
	}

	exit, ok := ts.fullExits[valPubkey]
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(writer).Encode(exit); err != nil {
		writeErr(writer, http.StatusInternalServerError, errors.Wrap(err, "cannot marshal exit message").Error())
		return
	}
}

func (ts *testServer) partialExitsMatch(newOne ExitBlob) bool {
	// get the last one
	exitsLen := len(ts.partialExits[newOne.PublicKey])
	last := ts.partialExits[newOne.PublicKey][exitsLen-1]

	return *last.SignedExitMessage.Message == *newOne.SignedExitMessage.Message
}

// GenerateTestServer generates a obol API mock test server.
// It returns a http.Handler to be served over HTTP, and a function to add cluster lock files to its database.
func GenerateTestServer(_ *testing.T) (http.Handler, func(lock cluster.Lock)) {
	ts := testServer{
		lock:         sync.Mutex{},
		partialExits: map[string]PartialExits{},
		lockFiles:    map[string]cluster.Lock{},
		fullExits:    map[string]ExitBlob{},
		authTokens:   map[string]map[string]bool{},
	}

	router := mux.NewRouter()

	router.Use(authMiddleware)

	router.HandleFunc(partialExitTmpl, ts.HandlePartialExit).Methods(http.MethodPost)
	router.HandleFunc(fullExitTmpl, ts.HandleFullExit).Methods(http.MethodGet)

	return router, ts.addLockFiles
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")
		bearer = strings.TrimSpace(bearer)
		if bearer == "" {
			writeErr(w, http.StatusUnauthorized, "missing authorization header")
		}

		r = r.WithContext(context.WithValue(r.Context(), tokenContextKey, bearer))

		// compare the return-value to the authMW
		next.ServeHTTP(w, r)
	})
}
