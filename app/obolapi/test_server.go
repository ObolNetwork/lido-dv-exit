// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/gorilla/mux"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
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

// exitBlob represents an Obol API ExitBlob with its share index.
type exitBlob struct {
	ExitBlob
	shareIdx int
}

// testServer is a mock implementation (but that actually does cryptography) of the Obol API side,
// which will handle storing and recollecting partial signatures.
type testServer struct {
	// for convenience, this thing handles one request at a time
	lock sync.Mutex

	// store the partial exits by the validator pubkey
	partialExits map[string][]exitBlob

	// store the lock file by its lock hash
	lockFiles map[string]cluster.Lock
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

	vars := mux.Vars(request)

	var data PartialExitRequest

	if err := json.NewDecoder(request.Body).Decode(&data); err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid body")
		return
	}

	lockHash := vars[cleanTmpl(lockHashPath)]
	if lockHash == "" {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	// check that data has been signed with ShareIdx-th identity key
	if data.ShareIdx == 0 || data.ShareIdx > len(lock.Operators) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	signedExitsRoot, err := data.HashTreeRoot()
	if err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot calculate hash tree root for provided signed exits")
		return
	}

	if err := verifyIdentitySignature(lock.Operators[data.ShareIdx-1], data.Signature, signedExitsRoot[:]); err != nil {
		writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
		return
	}

	for _, exit := range data.PartialExits {
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

		// check that the last partial exit's data is the same as the new one
		if len(ts.partialExits[exit.PublicKey]) > 0 && !ts.partialExitsMatch(exit) {
			writeErr(writer, http.StatusBadRequest, "wrong partial exit for the selected validator")
			return
		}

		if len(ts.partialExits[exit.PublicKey])+1 > len(lock.Operators) { // we're already at threshold
			writeErr(writer, http.StatusBadRequest, "already at threshold for selected validator")
			return
		}

		ts.partialExits[exit.PublicKey] = append(ts.partialExits[exit.PublicKey], exitBlob{
			ExitBlob: exit,
			shareIdx: data.ShareIdx,
		})
	}

	writer.WriteHeader(http.StatusCreated)
}

func (ts *testServer) HandleFullExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).([]byte)
	if !ok {
		log.Error(request.Context(), "received context without token, that's impossible!", nil)
		return
	}

	vars := mux.Vars(request)

	valPubkey := vars[cleanTmpl(valPubkeyPath)]
	lockHash := vars[cleanTmpl(lockHashPath)]
	shareIndexStr := vars[cleanTmpl(shareIndexPath)]
	shareIndex, err := strconv.Atoi(shareIndexStr)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "malformed share index")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	partialExits, ok := ts.partialExits[valPubkey]
	if !ok {
		writeErr(writer, http.StatusNotFound, "validator not found")
		return
	}

	if len(partialExits) < lock.Threshold {
		writeErr(writer, http.StatusUnauthorized, "not enough partial exits stored")
		return
	}

	// check that data has been signed with ShareIdx-th identity key
	if shareIndex == 0 || shareIndex > len(lock.Operators) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	if err := verifyIdentitySignature(lock.Operators[shareIndex-1], authToken, lock.LockHash); err != nil {
		writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
		return
	}

	var ret FullExitResponse

	// order partial exits by share index
	sort.Slice(partialExits, func(i, j int) bool {
		return partialExits[i].shareIdx < partialExits[j].shareIdx
	})

	for _, pExit := range partialExits {
		ret.Signatures = append(ret.Signatures, "0x"+hex.EncodeToString(pExit.SignedExitMessage.Signature[:]))
		ret.Epoch = strconv.FormatUint(uint64(pExit.SignedExitMessage.Message.Epoch), 10)
		ret.ValidatorIndex = pExit.SignedExitMessage.Message.ValidatorIndex
	}

	if err := json.NewEncoder(writer).Encode(ret); err != nil {
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

// verifyIdentitySignature verifies that sig for hash has been created with operator's identity key.
func verifyIdentitySignature(operator cluster.Operator, sig, hash []byte) error {
	opENR, err := enr.Parse(operator.ENR)
	if err != nil {
		return errors.Wrap(err, "operator enr")
	}

	signature, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return errors.Wrap(err, "read signature")
	}

	if !signature.Verify(hash, opENR.PubKey) {
		return errors.New("identity signature verification failed")
	}

	return nil
}

// cleanTmpl cleans tmpl from '{' and '}', used in path definitions.
func cleanTmpl(tmpl string) string {
	return strings.NewReplacer(
		"{",
		"",
		"}",
		"").Replace(tmpl)
}

// MockServer returns a obol API mock test server.
// It returns a http.Handler to be served over HTTP, and a function to add cluster lock files to its database.
func MockServer() (http.Handler, func(lock cluster.Lock)) {
	ts := testServer{
		lock:         sync.Mutex{},
		partialExits: map[string][]exitBlob{},
		lockFiles:    map[string]cluster.Lock{},
	}

	router := mux.NewRouter()

	full := router.PathPrefix(fullExitBaseTmpl).Subrouter()
	full.Use(authMiddleware)
	full.HandleFunc(fullExitEndTmp, ts.HandleFullExit).Methods(http.MethodGet)

	router.HandleFunc(partialExitTmpl, ts.HandlePartialExit).Methods(http.MethodPost)

	return router, ts.addLockFiles
}

// Run runs obol api mock on the provided bind port.
func Run(_ context.Context, bind string, locks []cluster.Lock) error {
	ms, addLock := MockServer()

	for _, lock := range locks {
		addLock(lock)
	}

	srv := http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           ms,
		Addr:              bind,
	}

	if err := srv.ListenAndServe(); err != nil {
		return errors.Wrap(err, "obol api mock error")
	}

	return nil
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")
		bearer = strings.TrimSpace(bearer)
		if bearer == "" {
			writeErr(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		bearerBytes, err := base64.StdEncoding.DecodeString(bearer)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bearer token must be base64-encoded")
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), tokenContextKey, bearerBytes))

		// compare the return-value to the authMW
		next.ServeHTTP(w, r)
	})
}
