// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keystore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	ckeystore "github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// KeyShare represents a share in the context of a Charon cluster,
// alongside its index.
type KeyShare struct {
	Share tbls.PrivateKey
	Index int
}

// ValidatorPubkey is a 0x-prefixed validator public key.
type ValidatorPubkey string

// Phase0 return vp as a phase0.BLSPubKey key.
func (vp ValidatorPubkey) Phase0() (phase0.BLSPubKey, error) {
	rawPubk, err := hex.DecodeString(string(vp[2:]))
	if err != nil {
		return phase0.BLSPubKey{}, errors.Wrap(err, "validator pubkey from hex")
	}

	tPubk, err := tblsconv.PubkeyFromBytes(rawPubk)
	if err != nil {
		return phase0.BLSPubKey{}, errors.Wrap(err, "validator pubkey from bytes")
	}

	pubk, err := tblsconv.PubkeyToETH2(tPubk)
	if err != nil {
		return phase0.BLSPubKey{}, errors.Wrap(err, "validator pubkey from tbls pubkey")
	}

	return pubk, nil
}

// ValidatorShares maps each ValidatorPubkey to the associated KeyShare.
type ValidatorShares map[ValidatorPubkey]KeyShare

// ValidatorsPhase0 returns validator keys from vs as their phase0.BLSPubKey versions.
func (vs ValidatorShares) ValidatorsPhase0() ([]phase0.BLSPubKey, error) {
	var ret []phase0.BLSPubKey

	for val := range vs {
		p0Val, err := val.Phase0()
		if err != nil {
			return nil, err
		}

		ret = append(ret, p0Val)
	}

	return ret, nil
}

// clusterFile returns the *manifestpb.Cluster file contained in dir.
func clusterFile(dir string) (*manifestpb.Cluster, error) {
	// try opening the lock file
	lockFile := filepath.Join(dir, "cluster-lock.json")
	manifestFile := filepath.Join(dir, "cluster-manifest.pb")

	cl, err := manifest.LoadCluster(manifestFile, lockFile, func(_ cluster.Lock) error {
		return nil // don't verify signatures, we don't care
	})

	if err != nil {
		return nil, errors.Wrap(err, "manifest load error")
	}

	return cl, nil
}

// LoadManifest loads a cluster manifest from one of the charon directories contained in dir.
// It checks that all the directories containing a validator_keys subdirectory contain the same manifest file, or lock file.
// loadManifest gives precedence to the manifest file.
// It returns the v1.Cluster contained in dir, and the set of private key shares contained in validator_keys.
func LoadManifest(dir string) (*manifestpb.Cluster, []tbls.PrivateKey, error) {
	_, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can't read directory")
	}

	cl, err := clusterFile(dir)
	if err != nil {
		return nil, nil, err
	}

	vcdPath := filepath.Join(dir, "validator_keys")
	_, err = os.ReadDir(vcdPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can't read validator_keys directory")
	}

	keyFiles, err := ckeystore.LoadFilesUnordered(vcdPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can't read key shares")
	}

	secrets, err := keyFiles.SequencedKeys()
	if err != nil {
		return nil, nil, errors.Wrap(err, "order private key shares")
	}

	return cl, secrets, nil
}

// loadIdentityKey loads the ENR identity key from dir.
func loadIdentityKey(dir string) (enr.Record, error) {
	key, err := k1util.Load(filepath.Join(dir, "charon-enr-private-key"))
	if err != nil {
		return enr.Record{}, errors.Wrap(err, "load priv key")
	}

	e, err := enr.New(key)
	if err != nil {
		return enr.Record{}, errors.Wrap(err, "enr new")
	}

	return e, nil
}

// ShareIdxForCluster returns the share index for the Charon cluster's ENR identity key, given a *manifestpb.Cluster.
func ShareIdxForCluster(dir string, cl *manifestpb.Cluster) (int, error) {
	pids, err := manifest.ClusterPeerIDs(cl)
	if err != nil {
		return 0, errors.Wrap(err, "cluster peer ids")
	}

	idKey, err := loadIdentityKey(dir)
	if err != nil {
		return 0, errors.Wrap(err, "enr")
	}

	k := crypto.Secp256k1PublicKey(*idKey.PubKey)

	shareIdx := -1
	for _, pid := range pids {
		if !pid.MatchesPublicKey(&k) {
			continue
		}

		nIdx, err := manifest.ClusterNodeIdx(cl, pid)
		if err != nil {
			return 0, errors.Wrap(err, "cluster node idx")
		}

		shareIdx = nIdx.ShareIdx
	}

	if shareIdx == -1 {
		return 0, errors.New("node index for loaded enr not found in cluster lock")
	}

	return shareIdx, nil
}

// AuthTokenFromIdentityKey returns the hash of the charon identity key associated with the node in base64 form.
func AuthTokenFromIdentityKey(dir string) (string, error) {
	idKey, err := loadIdentityKey(dir)
	if err != nil {
		return "", errors.Wrap(err, "enr")
	}

	h := sha256.Sum256(idKey.PubKey.SerializeCompressed())

	return base64.StdEncoding.EncodeToString(h[:]), nil
}

// KeyshareToValidatorPubkey maps each share in cl to the associated validator private key.
// It returns an error if a keyshare does not appear in cl, or if there's a validator public key associated to no
// keyshare.
func KeyshareToValidatorPubkey(cl *manifestpb.Cluster, shares []tbls.PrivateKey) (ValidatorShares, error) {
	ret := make(map[ValidatorPubkey]KeyShare)

	var pubShares []tbls.PublicKey

	for _, share := range shares {
		ps, err := tbls.SecretToPublicKey(share)
		if err != nil {
			return nil, errors.Wrap(err, "private share to public share")
		}

		pubShares = append(pubShares, ps)
	}

	// this is sadly a O(n^2) search
	for _, validator := range cl.Validators {
		valHex := fmt.Sprintf("0x%x", validator.PublicKey)

		valPubShares := make(map[tbls.PublicKey]struct{})
		for _, valShare := range validator.PubShares {
			valPubShares[tbls.PublicKey(valShare)] = struct{}{}
		}

		found := false
		for shareIdx, share := range pubShares {
			if _, ok := valPubShares[share]; !ok {
				continue
			}

			ret[ValidatorPubkey(valHex)] = KeyShare{
				Share: shares[shareIdx],
				Index: shareIdx + 1,
			}
			found = true
			break
		}

		if !found {
			return nil, errors.New("share from provided private key shares slice not found in provided manifest")
		}
	}

	if len(ret) != len(cl.Validators) {
		return nil, errors.New("amount of key shares don't match amount of validator public keys")
	}

	return ret, nil
}
