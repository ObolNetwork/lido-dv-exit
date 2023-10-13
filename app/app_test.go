// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	ckeystore "github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/ObolNetwork/lido-dv-exit/app"
	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
)

const exitEpoch = eth2p0.Epoch(194048)

func Test_RunFlow(t *testing.T) {
	valAmt := 4
	operatorAmt := 4

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		cluster.WithVersion("v1.7.0"),
	)

	operatorShares := make([][]tbls.PrivateKey, operatorAmt)

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		for _, share := range keyShares {
			operatorShares[opIdx] = append(operatorShares[opIdx], share[opIdx])
		}
	}

	dag, err := manifest.NewDAGFromLockForT(t, lock)
	require.NoError(t, err)

	mBytes, err := proto.Marshal(dag)
	require.NoError(t, err)

	baseDir := t.TempDir()
	ejectorDir := filepath.Join(t.TempDir(), "ejector")
	require.NoError(t, os.Mkdir(ejectorDir, 0o755))

	// write private keys and manifest files
	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		opID := fmt.Sprintf("op%d", opIdx)
		oDir := filepath.Join(baseDir, opID)
		eDir := filepath.Join(ejectorDir, opID)
		keysDir := filepath.Join(oDir, "validator_keys")
		manifestFile := filepath.Join(oDir, "cluster-manifest.pb")

		require.NoError(t, os.MkdirAll(oDir, 0o755))
		require.NoError(t, k1util.Save(enrs[opIdx], filepath.Join(oDir, "charon-enr-private-key")))

		require.NoError(t, os.MkdirAll(keysDir, 0o755))
		require.NoError(t, os.MkdirAll(eDir, 0o755))

		require.NoError(t, ckeystore.StoreKeysInsecure(operatorShares[opIdx], keysDir, ckeystore.ConfirmInsecureKeys))
		require.NoError(t, os.WriteFile(manifestFile, mBytes, 0o755))
	}

	// wire test server for obol api

	oapiHandler, oapiAddLock := obolapi.MockServer()
	oapiAddLock(lock)

	oapiServer := httptest.NewServer(oapiHandler)
	defer oapiServer.Close()

	// wire eth mock server

	mockValidators := map[string]eth2v1.Validator{}

	for _, val := range lock.Validators {
		mockValidators[val.PublicKeyHex()] = eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(rand.Int63()),
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:                  eth2p0.BLSPubKey(val.PubKey),
				WithdrawalCredentials:      testutil.RandomBytes32(),
				EffectiveBalance:           42,
				Slashed:                    false,
				ActivationEligibilityEpoch: 42,
				ActivationEpoch:            42,
				ExitEpoch:                  42,
				WithdrawableEpoch:          42,
			},
		}
	}

	bnapiHandler := bnapi.MockBeaconNode(mockValidators)
	bnapiServer := httptest.NewServer(bnapiHandler)
	defer bnapiServer.Close()

	runConfForIdx := func(idx int) app.Config {
		opID := fmt.Sprintf("op%d", idx)

		return app.Config{
			Log: log.Config{
				Level:  "debug",
				Format: "console",
				Color:  "false",
			},
			BeaconNodeURL:    bnapiServer.URL,
			EjectorExitPath:  filepath.Join(ejectorDir, opID),
			CharonRuntimeDir: filepath.Join(baseDir, opID),
			ObolAPIURL:       oapiServer.URL,
			ExitEpoch:        194048,
		}
	}

	eg := errgroup.Group{}

	ctx := context.Background()

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		opIdx := opIdx
		eg.Go(func() error {
			if err := app.Run(ctx, runConfForIdx(opIdx)); err != nil {
				return errors.Wrap(err, "app run")
			}

			return nil
		})
	}

	require.NoError(t, eg.Wait())

	mockEth2Cl := eth2Client(t, context.Background(), bnapiServer.URL)

	// check that all produced exit messages are signed by all partial keys for all operators
	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		opID := fmt.Sprintf("op%d", opIdx)

		ejectorDir := filepath.Join(ejectorDir, opID)

		for _, val := range lock.Validators {
			eFile := filepath.Join(ejectorDir, fmt.Sprintf("validator-exit-%s.json", val.PublicKeyHex()))

			fc, err := os.ReadFile(eFile)
			require.NoError(t, err)

			var exit eth2p0.SignedVoluntaryExit
			require.NoError(t, json.Unmarshal(fc, &exit))

			sigRoot, err := exit.Message.HashTreeRoot()
			require.NoError(t, err)

			domain, err := signing.GetDomain(context.Background(), mockEth2Cl, signing.DomainExit, exitEpoch)
			require.NoError(t, err)

			sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
			require.NoError(t, err)

			pubkBytes, err := val.PublicKey()
			require.NoError(t, err)

			require.NoError(t, tbls.Verify(pubkBytes, sigData[:], tbls.Signature(exit.Signature)))
		}
	}
}

func eth2Client(t *testing.T, ctx context.Context, bnURL string) eth2wrap.Client {
	t.Helper()

	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second)
}
