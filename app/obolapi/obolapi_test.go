package obolapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

func TestAPIFlow(t *testing.T) {
	kn := 4

	handler, addLockFiles := obolapi.GenerateTestServer(t)
	srv := httptest.NewServer(handler)

	defer srv.Close()

	lock, _, shares := cluster.NewForT(
		t,
		1,
		kn,
		kn,
		0,
	)

	addLockFiles(lock)

	exitMsg := obolapi.ExitMessage{
		Epoch:          "42",
		ValidatorIndex: "42",
	}

	exitMsgBytes, err := json.Marshal(exitMsg)
	require.NoError(t, err)

	emHash := sha256.Sum256(exitMsgBytes)

	var exits []obolapi.ExitBlob

	for idx, shareSet := range shares[0] {
		signature, err := tbls.Sign(shareSet, emHash[:])
		require.NoError(t, err)

		exits = append(exits, obolapi.ExitBlob{
			PublicKey:   lock.Validators[0].PublicKeyHex(),
			ExitMessage: exitMsg,
			Signature:   fmt.Sprintf("0x%x", signature[:]),
			ShareIdx:    idx + 1,
		})
	}

	lockHash := hex.EncodeToString(lock.LockHash)

	cl := obolapi.Client{ObolAPIUrl: srv.URL}

	// send all the partial exits
	for _, exit := range exits {
		require.NoError(t, cl.PostPartialExit(lockHash, exit))
	}

	// get full exit
	fullExit, err := cl.GetFullExit(lock.Validators[0].PublicKeyHex())
	require.NoError(t, err)

	valPubk, err := lock.Validators[0].PublicKey()
	require.NoError(t, err)

	rawSigBytes, err := hex.DecodeString(fullExit.Signature[2:])
	require.NoError(t, err)

	sig, err := tblsconv.SignatureFromBytes(rawSigBytes)
	require.NoError(t, err)

	// verify that the aggregated signature works
	require.NoError(t, tbls.Verify(valPubk, emHash[:], sig))
}
