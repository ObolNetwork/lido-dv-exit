// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1
package app_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	ckeystore "github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil/beaconmock"
	"github.com/obolnetwork/charon/testutil/obolapimock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/ObolNetwork/lido-dv-exit/app"
	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
)

type beaconMockWrap struct {
	bmock  beaconmock.Mock
	vals   func() beaconmock.ValidatorSet
	router http.Handler
}

func newBeaconMockWrap(t *testing.T, bmock beaconmock.Mock, vals func() beaconmock.ValidatorSet) beaconMockWrap {
	t.Helper()

	ret := beaconMockWrap{
		bmock: bmock,
		vals:  vals,
	}

	bmockURL, err := url.Parse(ret.bmock.Address())
	require.NoError(t, err)
	rp := httputil.NewSingleHostReverseProxy(bmockURL)

	oldDirector := rp.Director

	rp.Director = func(request *http.Request) {
		// This function attaches request IDs for the validators path into the context, so that
		// we can use them in the ModifyResponse handler.
		defer oldDirector(request)

		if request.URL.Path != "/eth/v1/beacon/states/head/validators" {
			return
		}

		type req struct {
			IDs []string `json:"ids"`
		}

		var r req

		require.NoError(t, json.NewDecoder(request.Body).Decode(&r))

		var writer bytes.Buffer
		require.NoError(t, json.NewEncoder(&writer).Encode(r))

		body := io.NopCloser(&writer)
		request.Body = body
		request.ContentLength = int64(writer.Len())

		//nolint:staticcheck // test case, it's fine
		*request = *request.WithContext(context.WithValue(request.Context(), "req_ids", r.IDs))
	}

	rp.ModifyResponse = func(response *http.Response) error {
		if response.Request.URL.Path != "/eth/v1/beacon/states/head/validators" {
			return nil
		}

		ctx := response.Request.Context()
		reqIDs := ctx.Value("req_ids").([]string)
		reqIDsMap := make(map[string]struct{})

		for _, r := range reqIDs {
			reqIDsMap[r] = struct{}{}
		}

		type getValidatorsResponse struct {
			Data []*eth2v1.Validator `json:"data"`
		}

		set := ret.vals()
		var resp getValidatorsResponse
		for _, v := range set {
			if _, ok := reqIDsMap[v.Validator.PublicKey.String()]; !ok {
				continue
			}

			resp.Data = append(resp.Data, v)
		}

		var writer bytes.Buffer

		require.NoError(t, json.NewEncoder(&writer).Encode(resp))

		body := io.NopCloser(&writer)
		response.Body = body
		response.ContentLength = int64(writer.Len())
		response.Header.Set("Content-Length", strconv.Itoa(writer.Len()))

		return nil
	}

	ret.router = rp

	return ret
}

type servers struct {
	obolAPI  *httptest.Server
	beacon   beaconmock.Mock
	bwrapSrv *httptest.Server
}

func (s *servers) Close() {
	s.obolAPI.Close()
	_ = s.beacon.Close()

	if s.bwrapSrv != nil {
		s.bwrapSrv.Close()
	}
}

// cloneValidator returns a cloned value that is safe for modification.
// taken from beaconmock for compat purposes.
func cloneValidator(val *eth2v1.Validator) *eth2v1.Validator {
	tempv1 := *val
	tempp0 := *tempv1.Validator
	tempv1.Validator = &tempp0

	return &tempv1
}

func validatorSetFromLock(lock cluster.Lock) beaconmock.ValidatorSet {
	vs := make(beaconmock.ValidatorSet)

	for idx, dv := range lock.Validators {
		idx := eth2p0.ValidatorIndex(idx + 1)
		vs[idx] = &eth2v1.Validator{
			Index:   idx,
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:                  eth2p0.BLSPubKey(dv.PubKey),
				WithdrawalCredentials:      dv.PubKey[:32],
				EffectiveBalance:           42,
				Slashed:                    false,
				ActivationEligibilityEpoch: 42,
				ActivationEpoch:            42,
				ExitEpoch:                  18446744073709551615,
				WithdrawableEpoch:          42,
			},
		}
	}

	return vs
}

func newServers(t *testing.T, lock cluster.Lock, validators func() beaconmock.ValidatorSet) servers {
	t.Helper()

	bmock, err := beaconmock.New(
		beaconmock.WithSlotDuration(1*time.Second),
		beaconmock.WithForkVersion([4]byte(lock.ForkVersion)),
		beaconmock.WithValidatorSet(validatorSetFromLock(lock)),
	)
	require.NoError(t, err)

	mockEth2Cl := eth2Client(t, context.Background(), bmock.Address())
	mockEth2Cl.SetForkVersion([4]byte(lock.ForkVersion))

	handler, addLock := obolapimock.MockServer(false, mockEth2Cl)
	addLock(lock)

	oapiServer := httptest.NewServer(handler)

	ret := servers{
		beacon:  bmock,
		obolAPI: oapiServer,
	}

	if validators != nil {
		bwrap := newBeaconMockWrap(t, ret.beacon, validators)
		ret.bwrapSrv = httptest.NewServer(bwrap.router)
	}

	return ret
}

func Test_NormalFlow(t *testing.T) {
	// TODO (kalo): WithForkVersion function is still missing from v1.4.3. Once it's added in v1.5, remove this skip.
	t.Skip()
	valAmt := 100
	operatorAmt := 4
	// fv, err := hex.DecodeString(strings.TrimPrefix(eth2util.Holesky.GenesisForkVersionHex, "0x"))
	// require.NoError(t, err)

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		rand.New(rand.NewSource(0)),
		cluster.WithVersion("v1.10.0"),
		// cluster.WithForkVersion(fv),
	)

	srvs := newServers(t, lock, nil)
	defer srvs.Close()

	run(t, t.TempDir(), lock, enrs, keyShares, true, srvs, false)
}

func Test_NormalFlowHalfHalfSingleRun(t *testing.T) {
	// TODO (kalo): WithForkVersion function is still missing from v1.4.3. Once it's added in v1.5, remove this skip.
	t.Skip()
	valAmt := 10
	operatorAmt := 4
	// fv, err := hex.DecodeString(strings.TrimPrefix(eth2util.Holesky.GenesisForkVersionHex, "0x"))
	// require.NoError(t, err)

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		rand.New(rand.NewSource(0)),
		cluster.WithVersion("v1.10.0"),
		// cluster.WithForkVersion(fv),
	)

	vs := validatorSetFromLock(lock)
	var vsLock sync.Mutex

	// set the first 5 as non-active
	for i := range 5 {
		vs[eth2p0.ValidatorIndex(i+1)].Status = eth2v1.ValidatorStatePendingQueued
	}

	srvs := newServers(t, lock, func() beaconmock.ValidatorSet {
		vsLock.Lock()
		defer vsLock.Unlock()

		cl := make(beaconmock.ValidatorSet)

		for _, v := range vs {
			cl[v.Index] = cloneValidator(v)
		}

		return cl
	})

	defer srvs.Close()

	go func() {
		// wait some time before setting everybody as read
		time.Sleep(3 * time.Second)

		vsLock.Lock()
		// set the first 5 as active
		for i := 0; i < 5; i++ {
			vs[eth2p0.ValidatorIndex(i+1)].Status = eth2v1.ValidatorStateActiveOngoing
		}
		vsLock.Unlock()
	}()

	run(t, t.TempDir(), lock, enrs, keyShares, true, srvs, false)
}

func Test_WithNonActiveVals(t *testing.T) {
	// TODO (kalo): WithForkVersion function is still missing from v1.4.3. Once it's added in v1.5, remove this skip.
	t.Skip()
	valAmt := 100
	operatorAmt := 4
	// fv, err := hex.DecodeString(strings.TrimPrefix(eth2util.Holesky.GenesisForkVersionHex, "0x"))
	// require.NoError(t, err)

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		rand.New(rand.NewSource(0)),
		cluster.WithVersion("v1.10.0"),
		// cluster.WithForkVersion(fv),
	)

	srvs := newServers(t, lock, nil)
	defer srvs.Close()

	td := t.TempDir()
	run(t, td, lock, enrs, keyShares, true, srvs, true)
}

func Test_RunTwice(t *testing.T) {
	// TODO (kalo): WithForkVersion function is still missing from v1.4.3. Once it's added in v1.5, remove this skip.
	t.Skip()
	valAmt := 4
	operatorAmt := 4
	// fv, err := hex.DecodeString(strings.TrimPrefix(eth2util.Holesky.GenesisForkVersionHex, "0x"))
	// require.NoError(t, err)

	lock, enrs, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		rand.New(rand.NewSource(0)),
		cluster.WithVersion("v1.10.0"),
		// cluster.WithForkVersion(fv),
	)

	srvs := newServers(t, lock, nil)
	defer srvs.Close()

	root := t.TempDir()

	run(t, root, lock, enrs, keyShares, true, srvs, false)

	// delete half exits from each ejector directory
	ejectorDir := filepath.Join(root, "ejector")

	for opID := range operatorAmt {
		ejectorOPPath := filepath.Join(ejectorDir, fmt.Sprintf("op%d", opID))

		exitPaths, err := filepath.Glob(filepath.Join(ejectorOPPath, "*.json"))
		require.NoError(t, err)

		for exitIdx := range len(exitPaths) / 2 {
			require.NoError(t, os.Remove(exitPaths[exitIdx]))
		}
	}

	run(t, root, lock, enrs, keyShares, false, srvs, false)
}

//nolint:thelper // this is the real test logic
func run(
	t *testing.T,
	root string,
	lock cluster.Lock,
	enrs []*k1.PrivateKey,
	keyShares [][]tbls.PrivateKey,
	createDirFiles bool,
	servers servers,
	withNonActiveVals bool,
) {
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
		for opIdx := range operatorAmt {
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

	bnURL := servers.beacon.Address()
	if servers.bwrapSrv != nil {
		bnURL = servers.bwrapSrv.URL
	}

	runConfForIdx := func(idx int) app.Config {
		opID := fmt.Sprintf("op%d", idx)

		return app.Config{
			Log: log.Config{
				Level:  "debug",
				Format: "console",
				Color:  "false",
			},
			BeaconNodeURL:           bnURL,
			EjectorExitPath:         filepath.Join(ejectorDir, opID),
			CharonRuntimeDir:        filepath.Join(root, opID),
			ObolAPIURL:              servers.obolAPI.URL,
			ExitEpoch:               194048,
			ValidatorQueryChunkSize: 1,
		}
	}

	eg := errgroup.Group{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for opIdx := range operatorAmt {
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
				for opIdx := range enrs {
					opID := fmt.Sprintf("op%d", opIdx)

					ejectorDir := filepath.Join(ejectorDir, opID)
					files, err := os.ReadDir(ejectorDir)
					if err != nil {
						halfExitsErrorChan <- err
					}

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

	mockEth2Cl := eth2Client(t, context.Background(), servers.beacon.Address())
	mockEth2Cl.SetForkVersion([4]byte(lock.ForkVersion))

	rawSpec, err := mockEth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	require.NoError(t, err)

	spec := rawSpec.Data

	genesis, err := mockEth2Cl.Genesis(ctx, &eth2api.GenesisOpts{})
	require.NoError(t, err)

	forkHash, err := bnapi.CapellaFork("0x" + hex.EncodeToString(genesis.Data.GenesisForkVersion[:]))
	require.NoError(t, err)

	genesisValidatorRoot := genesis.Data.GenesisValidatorsRoot

	// check that all produced exit messages are signed by all partial keys for all operators
	for opIdx := range operatorAmt {
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

func eth2Client(t *testing.T, ctx context.Context, u string) eth2wrap.Client {
	t.Helper()

	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(u),
		eth2http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, nil, 1*time.Second)
}
