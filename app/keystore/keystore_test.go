// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	ckeystore "github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/ObolNetwork/lido-dv-exit/app/keystore"
)

func TestKeyshareToValidatorPubkey(t *testing.T) {
	valAmt := 4
	sharesAmt := 10

	privateShares := make([]tbls.PrivateKey, valAmt)

	cl := &manifestpb.Cluster{}

	for valIdx := 0; valIdx < valAmt; valIdx++ {
		valPubk, err := tblsconv.PubkeyFromCore(testutil.RandomCorePubKey(t))
		require.NoError(t, err)

		validator := &manifestpb.Validator{
			PublicKey: valPubk[:],
		}

		randomShareSelected := false

		for shareIdx := 0; shareIdx < sharesAmt; shareIdx++ {
			sharePriv, err := tbls.GenerateSecretKey()
			require.NoError(t, err)

			sharePub, err := tbls.SecretToPublicKey(sharePriv)
			require.NoError(t, err)

			if testutil.RandomBool() && !randomShareSelected {
				privateShares[valIdx] = sharePriv
				randomShareSelected = true
			}

			validator.PubShares = append(validator.PubShares, sharePub[:])
		}

		rand.Shuffle(len(validator.GetPubShares()), func(i, j int) {
			validator.PubShares[i], validator.PubShares[j] = validator.GetPubShares()[j], validator.GetPubShares()[i]
		})

		cl.Validators = append(cl.Validators, validator)
	}

	ret, err := keystore.KeyshareToValidatorPubkey(cl, privateShares)
	require.NoError(t, err)

	require.Len(t, ret, 4)

	for valPubKey, sharePrivKey := range ret {
		valFound := false
		sharePrivKeyFound := false

		for _, val := range cl.GetValidators() {
			if string(valPubKey) == fmt.Sprintf("0x%x", val.GetPublicKey()) {
				valFound = true
				break
			}
		}

		for _, share := range privateShares {
			if bytes.Equal(share[:], sharePrivKey.Share[:]) {
				sharePrivKeyFound = true
				break
			}
		}

		require.True(t, valFound, "validator pubkey not found")
		require.True(t, sharePrivKeyFound, "share priv key not found")
	}
}

func TestLoadManifest(t *testing.T) {
	valAmt := 4
	operatorAmt := 10

	lock, _, keyShares := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		rand.New(rand.NewSource(0)),
		cluster.WithVersion("v1.10.0"),
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

	cl, err := manifest.Materialise(dag)
	require.NoError(t, err)

	clBytes, err := proto.Marshal(cl)
	require.NoError(t, err)

	baseDir := t.TempDir()

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		oDir := filepath.Join(baseDir, fmt.Sprintf("op%d", opIdx))
		keysDir := filepath.Join(oDir, "validator_keys")
		manifestFile := filepath.Join(oDir, "cluster-manifest.pb")

		require.NoError(t, os.MkdirAll(keysDir, 0o755))

		require.NoError(t, ckeystore.StoreKeysInsecure(operatorShares[opIdx], keysDir, ckeystore.ConfirmInsecureKeys))
		require.NoError(t, os.WriteFile(manifestFile, mBytes, 0o755))

		readCl, readKeys, err := keystore.LoadManifest(oDir)
		require.NoError(t, err)

		readMBytes, err := proto.Marshal(readCl)
		require.NoError(t, err)

		require.Equal(t, clBytes, readMBytes)
		require.Equal(t, operatorShares[opIdx], readKeys)
	}

	for _, opKeys := range operatorShares {
		m, err := keystore.KeyshareToValidatorPubkey(cl, opKeys)
		require.NoError(t, err)
		require.Len(t, m, valAmt)
	}
}

func Test_PeerIDFromIdentity(t *testing.T) {
	valAmt := 4
	operatorAmt := 10

	_, identityKeys, _ := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		rand.New(rand.NewSource(0)),
		cluster.WithVersion("v1.10.0"),
	)

	baseDir := t.TempDir()

	for opIdx := 0; opIdx < operatorAmt; opIdx++ {
		oDir := filepath.Join(baseDir, fmt.Sprintf("op%d", opIdx))
		idKeyFile := filepath.Join(oDir, "charon-enr-private-key")
		require.NoError(t, os.MkdirAll(oDir, 0o755))
		require.NoError(t, os.WriteFile(idKeyFile, []byte(hex.EncodeToString(identityKeys[opIdx].Serialize())), 0o755))

		id, err := keystore.PeerIDFromIdentity(oDir)
		require.NoError(t, err)
		t.Log(id.String())
	}
}
