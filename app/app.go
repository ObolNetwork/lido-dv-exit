// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/keystore"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
	"github.com/ObolNetwork/lido-dv-exit/app/util"
)

// Config is the lido-dv-exit CLI configuration flag value holder.
type Config struct {
	Log              log.Config
	BeaconNodeURL    string
	EjectorExitPath  string
	CharonRuntimeDir string
	ExitEpoch        uint64
	ObolAPIURL       string
}

// Run runs the lido-dv-exit core logic.
func Run(ctx context.Context, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cl, keys, err := keystore.LoadManifest(config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "keystore load error")
	}

	shareIdx, err := keystore.ShareIdxForCluster(config.CharonRuntimeDir, cl)
	if err != nil {
		return errors.Wrap(err, "share idx for cluster")
	}

	identityKey, err := keystore.IdentityPrivateKey(config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "identity key loading")
	}

	ctx = log.WithCtx(ctx, z.U64("share_idx", shareIdx))

	log.Info(ctx, "Lido-dv-exit starting")

	valsKeys, err := keystore.KeyshareToValidatorPubkey(cl, keys)
	if err != nil {
		return errors.Wrap(err, "keystore load error")
	}

	existingValIndices, err := loadExistingValidatorExits(config.EjectorExitPath)
	if err != nil {
		return err
	}

	// TODO(gsora): cross-check the lido-ejector exits already present with valsKeys, so that we don't
	// re-process what's already been processed.

	bnClient, err := eth2Client(ctx, config.BeaconNodeURL)
	if err != nil {
		return errors.Wrap(err, "can't connect to beacon node")
	}

	oAPI := obolapi.Client{ObolAPIUrl: config.ObolAPIURL}

	tick := time.NewTicker(1 * time.Second)

	var signedExits []obolapi.ExitBlob

	for range tick.C {
		if len(valsKeys) == 0 {
			break // we finished signing everything we had to sign
		}

		phase0Vals, err := valsKeys.ValidatorsPhase0()
		if err != nil {
			return errors.Wrap(err, "validator keys to phase0")
		}

		valIndices, err := bnClient.ValidatorsByPubKey(ctx, bnapi.StateIDHead.String(), phase0Vals)
		if err != nil {
			log.Error(ctx, "Cannot fetch validator state", err)
			continue
		}

		for valIndex, val := range valIndices {
			validatorPubkStr := val.Validator.PublicKey.String()

			ctx := log.WithCtx(ctx, z.Str("validator", validatorPubkStr))

			if _, ok := existingValIndices[valIndex]; ok {
				// we already have an exit for this validator, remove it from the list and don't
				// process it
				log.Debug(ctx, "Validator already has an exit", z.U64("validx", uint64(valIndex)))
				delete(valsKeys, keystore.ValidatorPubkey(validatorPubkStr))

				continue
			}

			if !shouldProcessValidator(val) {
				log.Debug(ctx, "Not processing validator", z.Str("state", val.Status.String()))
				continue
			}

			valKeyShare, found := valsKeys[keystore.ValidatorPubkey(validatorPubkStr)]
			if !found {
				log.Warn(ctx, "Found validator to process which doesn't have available keyshare", nil)
				continue
			}

			// sign exit
			exit, err := signExit(ctx, bnClient, valIndex, valKeyShare.Share, eth2p0.Epoch(config.ExitEpoch))
			if err != nil {
				log.Error(ctx, "Cannot sign exit", err)
				continue
			}

			log.Debug(ctx, "Signed exit")
			signedExits = append(signedExits, obolapi.ExitBlob{
				PublicKey:         validatorPubkStr,
				SignedExitMessage: exit,
			})

			delete(valsKeys, keystore.ValidatorPubkey(validatorPubkStr))
		}
	}

	// send signed  exit to obol api
	for range tick.C {
		// we're retrying every second until we succeed
		if postPartialExit(ctx, oAPI, cl.GetInitialMutationHash(), shareIdx, identityKey, signedExits...) {
			tick.Stop()
			break
		}
	}

	type fetchExitData struct {
		lockHash        []byte
		validatorPubkey string
		shareIndex      uint64
		identityKey     *k1.PrivateKey
	}

	fork, join, fjcancel := forkjoin.New(ctx, func(ctx context.Context, data fetchExitData) (struct{}, error) {
		tick := time.NewTicker(1 * time.Second)
		defer tick.Stop()

		exitFSPath := filepath.Join(config.EjectorExitPath, fmt.Sprintf("validator-exit-%s.json", data.validatorPubkey))

		for range tick.C {
			if fetchFullExit(ctx, bnClient, oAPI, data.lockHash, data.validatorPubkey, exitFSPath, data.shareIndex, data.identityKey) {
				break
			}
		}

		return struct{}{}, nil
	}, forkjoin.WithWorkers(10), forkjoin.WithWaitOnCancel())

	defer fjcancel()

	for _, se := range signedExits {
		fork(fetchExitData{
			lockHash:        cl.InitialMutationHash,
			validatorPubkey: se.PublicKey,
			shareIndex:      shareIdx,
			identityKey:     identityKey,
		})
	}

	_, err = join().Flatten()

	if err != nil && !errors.Is(err, context.Canceled) {
		return errors.Wrap(err, "fatal error while processing full exits from obol api, please get in contact with the development team as soon as possible, with a full log of the execution")
	}

	log.Info(ctx, "Successfully fetched exit messages!")

	return nil
}

// fetchFullExit returns true if a full exit was received from the Obol API, and was written in exitFSPath.
// Each HTTP request has a 10 seconds timeout.
func fetchFullExit(ctx context.Context, eth2Cl eth2wrap.Client, oAPI obolapi.Client, lockHash []byte, validatorPubkey, exitFSPath string, shareIndex uint64, identityKey *k1.PrivateKey) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fullExit, err := oAPI.GetFullExit(ctx, validatorPubkey, lockHash, shareIndex, identityKey)
	if err != nil {
		if !errors.Is(err, obolapi.ErrNoExit) {
			log.Warn(ctx, "Cannot fetch full exit from obol api, will retry", err)
		}

		return false
	}

	data, err := fullExit.SignedExitMessage.MarshalJSON()
	if err != nil {
		log.Warn(ctx, "Cannot marshal exit to json", err)

		return false
	}

	// parse validator public key
	rawPkBytes, err := util.ValidatorPubkeyToBytes(validatorPubkey)
	if err != nil {
		log.Error(ctx, "Cannot decode validator public key", err)

		return false
	}

	pubkey, err := tblsconv.PubkeyFromBytes(rawPkBytes)
	if err != nil {
		log.Error(ctx, "Cannot convert public key to tbls type", err)

		return false
	}

	// parse signature
	signature, err := tblsconv.SignatureFromBytes(fullExit.SignedExitMessage.Signature[:])
	if err != nil {
		log.Error(ctx, "Cannot convert public key to tbls type", err)

		return false
	}

	exitRoot, err := sigDataForExit(ctx, *fullExit.SignedExitMessage.Message, eth2Cl, fullExit.SignedExitMessage.Message.Epoch)
	if err != nil {
		log.Error(ctx, "Cannot calculate hash tree root for exit message for verification", err)

		return false
	}

	if err := tbls.Verify(pubkey, exitRoot[:], signature); err != nil {
		log.Error(ctx, "Exit message signature not verified", err)

		return false
	}

	//nolint:gosec // must be wide open
	if err := os.WriteFile(exitFSPath, data, 0o755); err != nil {
		log.Warn(ctx, "Cannot write exit to filesystem path", err, z.Str("destination_path", exitFSPath))
		return false
	}

	return true
}

func postPartialExit(ctx context.Context, oAPI obolapi.Client, mutationHash []byte, shareIndex uint64, identityKey *k1.PrivateKey, exitBlobs ...obolapi.ExitBlob) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// we're retrying every second until we succeed
	if err := oAPI.PostPartialExit(ctx, mutationHash, shareIndex, identityKey, exitBlobs...); err != nil {
		log.Error(ctx, "Cannot post exits to obol api", err)
		return false
	}

	return true
}

// shouldProcessValidator returns true if a validator needs to be processed, meaning a full exit message must
// be created.
func shouldProcessValidator(v *eth2v1.Validator) bool {
	return v.Status == eth2v1.ValidatorStateActiveOngoing
}

// signExit signs a voluntary exit message for valIdx with the given keyShare.
// Adapted from charon.
func signExit(ctx context.Context, eth2Cl eth2wrap.Client, valIdx eth2p0.ValidatorIndex, keyShare tbls.PrivateKey, exitEpoch eth2p0.Epoch) (eth2p0.SignedVoluntaryExit, error) {
	exit := &eth2p0.VoluntaryExit{
		Epoch:          exitEpoch,
		ValidatorIndex: valIdx,
	}

	sigData, err := sigDataForExit(ctx, *exit, eth2Cl, exitEpoch)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "exit hash tree root")
	}

	sig, err := tbls.Sign(keyShare, sigData[:])
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "signing error")
	}

	return eth2p0.SignedVoluntaryExit{
		Message:   exit,
		Signature: eth2p0.BLSSignature(sig),
	}, nil
}

// sigDataForExit returns the hash tree root for the given exit message, at the given exit epoch.
func sigDataForExit(ctx context.Context, exit eth2p0.VoluntaryExit, eth2Cl eth2wrap.Client, exitEpoch eth2p0.Epoch) ([32]byte, error) {
	sigRoot, err := exit.HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "exit hash tree root")
	}

	domain, err := signing.GetDomain(ctx, eth2Cl, signing.DomainExit, exitEpoch)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "get domain")
	}

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data hash tree root")
	}

	return sigData, nil
}

// eth2Client initializes an eth2 beacon node API client.
func eth2Client(ctx context.Context, bnURL string) (eth2wrap.Client, error) {
	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(1), // zerolog.InfoLevel
	)
	if err != nil {
		return nil, errors.Wrap(err, "can't connect to beacon node")
	}

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second), nil
}

// loadExistingValidatorExits reads the indices for validators whose exits have been already processed.
func loadExistingValidatorExits(ejectorPath string) (map[eth2p0.ValidatorIndex]struct{}, error) {
	exitPaths, err := filepath.Glob(filepath.Join(ejectorPath, "*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "ejector exits glob")
	}

	ret := map[eth2p0.ValidatorIndex]struct{}{}

	if len(exitPaths) == 0 {
		return ret, nil
	}

	for _, ep := range exitPaths {
		exitBytes, err := os.ReadFile(ep)
		if err != nil {
			return nil, errors.Wrap(err, "read exit file", z.Str("path", ep))
		}

		var exit eth2p0.SignedVoluntaryExit
		if err := json.Unmarshal(exitBytes, &exit); err != nil {
			return nil, errors.Wrap(err, "unmarshal exit file", z.Str("path", ep))
		}

		ret[exit.Message.ValidatorIndex] = struct{}{}
	}

	return ret, nil
}
