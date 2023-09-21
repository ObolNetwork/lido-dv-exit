// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ethApi "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/keystore"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
)

// Config is the lido-dv-exit CLI configuration flag value holder.
type Config struct {
	Log log.Config

	// TODO: check that's a real URL
	BeaconNodeURL string

	// TODO: check if the directory exists and that is writable.
	EjectorExitPath string

	// TODO: check that the directory exists, keystore.LoadManifest will check the format is appropriate.
	CharonRuntimeDir string

	ObolAPIURL string
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

	ctx = log.WithCtx(ctx, z.Int("share_idx", shareIdx))

	log.Info(ctx, "Lido-dv-exit starting")

	valsKeys, err := keystore.KeyshareToValidatorPubkey(cl, keys)
	if err != nil {
		return errors.Wrap(err, "keystore load error")
	}

	// TODO(gsora): cross-check the lido-ejector exits already present with valsKeys, so that we don't
	// re-process what's already been processed.

	bnClient, err := eth2Client(ctx, config.BeaconNodeURL)
	if err != nil {
		return errors.Wrap(err, "can't connect to beacon node")
	}

	// TODO(gsora): check obol api url, see if correct
	oApi := obolapi.Client{ObolAPIUrl: config.ObolAPIURL}

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

		// TODO(gsora): calling with finalized here, need to understand what's better
		valIndices, err := bnClient.ValidatorsByPubKey(ctx, bnapi.StateIDFinalized.String(), phase0Vals)
		if err != nil {
			log.Error(ctx, "Cannot fetch validator state", err)
			continue
		}

		for valIndex, val := range valIndices {
			validatorPubkStr := val.Validator.PublicKey.String()

			ctx := log.WithCtx(ctx, z.Str("validator", validatorPubkStr))

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
			exit, err := signExit(ctx, bnClient, valIndex, valKeyShare.Share)
			if err != nil {
				log.Error(ctx, "Cannot sign exit", err)
				continue
			}

			log.Debug(ctx, "Signed exit")
			signedExits = append(signedExits, obolapi.ExitBlob{
				PublicKey:         validatorPubkStr,
				SignedExitMessage: exit,
				ShareIdx:          shareIdx,
			})

			delete(valsKeys, keystore.ValidatorPubkey(validatorPubkStr))
		}
	}

	// send signed  exit to obol api
	for range tick.C {
		// we're retrying every second until we succeeed
		if err := oApi.PostPartialExit("0x"+hex.EncodeToString(cl.GetInitialMutationHash()), signedExits...); err != nil {
			log.Error(ctx, "Cannot post exits to obol api", err)
			continue
		}

		tick.Stop()
		break
	}

	fork, join, fjcancel := forkjoin.New(ctx, func(ctx context.Context, validatorPubkey string) (struct{}, error) {
		tick := time.NewTicker(1 * time.Second)
		defer tick.Stop()

		exitFSPath := filepath.Join(config.EjectorExitPath, fmt.Sprintf("validator-exit-%s.json", validatorPubkey))

		for range tick.C {
			fullExit, err := oApi.GetFullExit(validatorPubkey)
			if err != nil {
				if !errors.Is(err, obolapi.ErrNoExit) {
					log.Warn(ctx, "Cannot fetch full exit from obol api, will retry", err)
				}
				continue
			}

			data, err := json.Marshal(fullExit)
			if err != nil {
				log.Warn(ctx, "Cannot marshal exit to json", err)
				continue
			}

			if err := os.WriteFile(exitFSPath, data, 0755); err != nil {
				log.Warn(ctx, "Cannot write exit to filesystem path", err, z.Str("destination_path", exitFSPath))
			}

			break
		}

		return struct{}{}, nil
	}, forkjoin.WithWorkers(10), forkjoin.WithWaitOnCancel())

	defer fjcancel()

	for _, se := range signedExits {
		fork(se.PublicKey)
	}

	_, err = join().Flatten()

	if err != nil {
		return errors.Wrap(err, "fatal error while processing full exits from obol api, please get in contact with the development team as soon as possible, with a full log of the execution!")
	}

	log.Info(ctx, "Successfully fetched exit messages!")

	return nil
}

// TODO(gsora): check this logic with the team
func shouldProcessValidator(v *ethApi.Validator) bool {
	return v.Status == ethApi.ValidatorStateActiveOngoing
}

const exitEpoch = eth2p0.Epoch(162304) // TODO(gsora): figure this out

// signExit signs a voluntary exit message for valIdx with the given keyShare.
// Adapted from charon.
func signExit(ctx context.Context, eth2Cl eth2wrap.Client, valIdx eth2p0.ValidatorIndex, keyShare tbls.PrivateKey) (eth2p0.SignedVoluntaryExit, error) {
	exit := &eth2p0.VoluntaryExit{
		Epoch:          exitEpoch,
		ValidatorIndex: valIdx,
	}

	sigRoot, err := exit.HashTreeRoot()
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "exit hash tree root")
	}

	domain, err := signing.GetDomain(ctx, eth2Cl, signing.DomainExit, exitEpoch)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "get domain")
	}

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "signing data hash tree root")
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

// eth2Client initializes an eth2 beacon node API client.
func eth2Client(ctx context.Context, bnURL string) (eth2wrap.Client, error) {
	bnHttpClient, err := http.New(ctx,
		http.WithAddress(bnURL),
		http.WithLogLevel(1), // zerolog.InfoLevel
	)

	if err != nil {
		return nil, errors.Wrap(err, "can't connect to beacon node")
	}

	bnClient := bnHttpClient.(*http.Service)
	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second), nil
}
