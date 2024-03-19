// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	ckeystore "github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/ObolNetwork/lido-dv-exit/app"
	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/util/testutil"
)

func Test_NormalFlow(t *testing.T) {
	valAmt := 100
	operatorAmt := 4

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		cluster.WithVersion("v1.7.0"),
	)

	srvs := testutil.APIServers(t, lock, false)
	defer srvs.Close()

	run(t,
		t.TempDir(),
		lock,
		enrs,
		keyShares,
		true,
		srvs,
		false,
	)
}

func Test_WithNonActiveVals(t *testing.T) {
	valAmt := 100
	operatorAmt := 4

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		cluster.WithVersion("v1.7.0"),
	)

	srvs := testutil.APIServers(t, lock, true)
	defer srvs.Close()

	td := t.TempDir()
	run(t,
		td,
		lock,
		enrs,
		keyShares,
		true,
		srvs,
		true,
	)
}

func Test_RunTwice(t *testing.T) {
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

	srvs := testutil.APIServers(t, lock, false)
	defer srvs.Close()

	root := t.TempDir()

	run(t,
		root,
		lock,
		enrs,
		keyShares,
		true,
		srvs,
		false,
	)

	// delete half exits from each ejector directory
	ejectorDir := filepath.Join(root, "ejector")

	for opID := 0; opID < operatorAmt; opID++ {
		ejectorOPPath := filepath.Join(ejectorDir, fmt.Sprintf("op%d", opID))

		exitPaths, err := filepath.Glob(filepath.Join(ejectorOPPath, "*.json"))
		require.NoError(t, err)

		for exitIdx := 0; exitIdx < len(exitPaths)/2; exitIdx++ {
			require.NoError(t, os.Remove(exitPaths[exitIdx]))
		}
	}

	run(t,
		root,
		lock,
		enrs,
		keyShares,
		false,
		srvs,
		false,
	)
}

func run(
	t *testing.T,
	root string,
	lock cluster.Lock,
	enrs []*k1.PrivateKey,
	keyShares [][]tbls.PrivateKey,
	createDirFiles bool,
	servers testutil.TestServers,
	withNonActiveVals bool,
) {
	t.Helper()

	operatorAmt := len(lock.Operators)

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

	ejectorDir := filepath.Join(root, "ejector")

	if createDirFiles {
		require.NoError(t, os.Mkdir(ejectorDir, 0o755))

		// write private keys and manifest files
		for opIdx := 0; opIdx < operatorAmt; opIdx++ {
			opID := fmt.Sprintf("op%d", opIdx)
			oDir := filepath.Join(root, opID)
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
	}

	runConfForIdx := func(idx int) app.Config {
		opID := fmt.Sprintf("op%d", idx)

		return app.Config{
			Log: log.Config{
				Level:  "debug",
				Format: "console",
				Color:  "false",
			},
			BeaconNodeURL:           servers.BeaconNodeServer.URL,
			EjectorExitPath:         filepath.Join(ejectorDir, opID),
			CharonRuntimeDir:        filepath.Join(root, opID),
			ObolAPIURL:              servers.ObolAPIServer.URL,
			ExitEpoch:               194048,
			ValidatorQueryChunkSize: 1,
		}
	}

	eg := errgroup.Group{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		opIdx := opIdx
		eg.Go(func() error {
			if err := app.Run(ctx, runConfForIdx(opIdx)); err != nil {
				return errors.Wrap(err, "app run")
			}

			return nil
		})
	}

	egErrorChan := make(chan error)
	halfExitsErrorChan := make(chan error)

	go func() {
		egErrorChan <- eg.Wait()
	}()

	if withNonActiveVals {
		// when withNonActiveVals is true, it means that we'll only produce half of the
		// full exits.
		go func() {
			stop := false

			for !stop {
				for opIdx := 0; opIdx < len(enrs); opIdx++ {
					opID := fmt.Sprintf("op%d", opIdx)

					ejectorDir := filepath.Join(ejectorDir, opID)
					files, err := os.ReadDir(ejectorDir)
					require.NoError(t, err)

					if len(files) >= len(keyShares[opIdx])/2 {
						cancel() // stop everything, test's alright
						halfExitsErrorChan <- nil
						stop = true
					}
				}
				runtime.Gosched() // yield a little
			}
		}()
	}

	stop := false
	for !stop {
		select {
		case err := <-egErrorChan:
			require.NoError(t, err)
			stop = true

		case err := <-halfExitsErrorChan:
			require.NoError(t, err)
			return
		}
	}

	mockEth2Cl := servers.Eth2Client(t, context.Background())

	rawSpec, err := mockEth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)

	spec := rawSpec.Data

	genesis, err := mockEth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	require.NoError(t, err)

	forkHash, err := bnapi.CapellaFork("0x" + hex.EncodeToString(genesis.Data.GenesisForkVersion[:]))
	require.NoError(t, err)

	genesisValidatorRoot := genesis.Data.GenesisValidatorsRoot

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

			domainType, ok := spec["DOMAIN_VOLUNTARY_EXIT"]
			require.True(t, ok)

			domainTyped, ok := domainType.(eth2p0.DomainType)
			require.True(t, ok)

			domain, err := bnapi.ComputeDomain(forkHash, domainTyped, genesisValidatorRoot)
			require.NoError(t, err)

			sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
			require.NoError(t, err)

			pubkBytes, err := val.PublicKey()
			require.NoError(t, err)

			require.NoError(t, tbls.Verify(pubkBytes, sigData[:], tbls.Signature(exit.Signature)))
		}
	}
}
