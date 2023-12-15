// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/jonboulle/clockwork"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/p2p"
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

const (
	maxBeaconNodeTimeout = 10 * time.Second
)

// Run runs the lido-dv-exit core logic.
func Run(ctx context.Context, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cl, keys, err := keystore.LoadManifest(config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "keystore load error")
	}

	peerID, err := keystore.PeerIDFromIdentity(config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "can't derive peer id")
	}

	// Logging labels.
	labels := map[string]string{
		"lde_cluster_hash": hex.EncodeToString(cl.InitialMutationHash),
		"lde_cluster_name": cl.Name,
		"lde_cluster_peer": p2p.PeerName(peerID),
		"lde_version":      util.GitHash(),
	}
	log.SetLokiLabels(labels)

	shareIdx, err := keystore.ShareIdxForCluster(config.CharonRuntimeDir, cl)
	if err != nil {
		return errors.Wrap(err, "share idx for cluster")
	}

	identityKey, err := keystore.IdentityPrivateKey(config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "identity key loading")
	}

	ctx = log.WithCtx(ctx, z.U64("share_idx", shareIdx), z.Str("peer_name", p2p.PeerName(peerID)))

	log.Info(ctx, "Lido-dv-exit starting")

	valsKeys, err := keystore.KeyshareToValidatorPubkey(cl, keys)
	if err != nil {
		return errors.Wrap(err, "keystore load error")
	}

	existingValIndices, err := loadExistingValidatorExits(config.EjectorExitPath)
	if err != nil {
		return err
	}

	bnClient, err := eth2Client(ctx, config.BeaconNodeURL, uint64(len(valsKeys)))
	if err != nil {
		return errors.Wrap(err, "can't connect to beacon node")
	}

	slotTicker, err := newSlotTicker(ctx, bnClient, clockwork.NewRealClock())
	if err != nil {
		return errors.Wrap(err, "can't subscribe to slot")
	}

	oAPI := obolapi.Client{ObolAPIUrl: config.ObolAPIURL}

	var signedExits []obolapi.ExitBlob
	fetchedSignedExits := map[string]struct{}{}

	for slot := range slotTicker {
		if len(valsKeys) == 0 {
			break // we finished signing everything we had to sign
		}

		if !slot.FirstInEpoch() {
			log.Debug(ctx, "Slot not first in epoch, not doing anything", z.U64("epoch", slot.Epoch()), z.U64("slot", slot.Slot))
			continue
		}

		log.Info(ctx, "Signing exit for available validators...", z.Int("available_validators", len(valsKeys)))

		// signedExitsInRound holds the signed partial exits generated at this epoch's lifecycle round
		var signedExitsInRound []obolapi.ExitBlob

		phase0Vals, err := valsKeys.ValidatorsPhase0()
		if err != nil {
			return errors.Wrap(err, "validator keys to phase0")
		}

		rawValIndices, err := bnClient.Validators(ctx, &eth2api.ValidatorsOpts{
			State:   bnapi.StateIDHead.String(),
			PubKeys: phase0Vals,
		})
		if err != nil {
			log.Error(ctx, "Cannot fetch validator state", err)
			continue
		}

		valIndices := rawValIndices.Data

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

			log.Info(ctx, "Signed partial exit")
			signedExitsInRound = append(signedExitsInRound, obolapi.ExitBlob{
				PublicKey:         validatorPubkStr,
				SignedExitMessage: exit,
			})
		}

		if len(signedExitsInRound) != 0 {
			// try posting the partial exits that have been produced at this stage
			if err := postPartialExit(ctx, oAPI, cl.GetInitialMutationHash(), shareIdx, identityKey, signedExitsInRound...); err != nil {
				log.Error(ctx, "Cannot post exits to obol api, will retry later", err)
			} else {
				for _, signedExit := range signedExitsInRound {
					delete(valsKeys, keystore.ValidatorPubkey(signedExit.PublicKey))
				}
			}

			signedExits = append(signedExits, signedExitsInRound...)
		}

		for _, signedExit := range signedExits {
			if _, ok := fetchedSignedExits[signedExit.PublicKey]; ok {
				continue // bypass already-fetched full exit
			}

			exitFSPath := filepath.Join(config.EjectorExitPath, fmt.Sprintf("validator-exit-%s.json", signedExit.PublicKey))

			if !fetchFullExit(ctx, bnClient, oAPI, cl.InitialMutationHash, signedExit.PublicKey, exitFSPath, shareIdx, identityKey) {
				log.Debug(ctx, "Could not fetch full exit for validator", z.Str("validator", signedExit.PublicKey))
				continue
			}

			fetchedSignedExits[signedExit.PublicKey] = struct{}{}
		}

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

// postPartialExit posts exitBlobs to Obol API with a 10 seconds HTTP request deadline.
func postPartialExit(ctx context.Context, oAPI obolapi.Client, mutationHash []byte, shareIndex uint64, identityKey *k1.PrivateKey, exitBlobs ...obolapi.ExitBlob) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := oAPI.PostPartialExit(ctx, mutationHash, shareIndex, identityKey, exitBlobs...); err != nil {
		return errors.Wrap(err, "cannot post partial exit")
	}

	return nil
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
func eth2Client(ctx context.Context, bnURL string, valAmount uint64) (eth2wrap.Client, error) {
	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(1), // zerolog.InfoLevel
		eth2http.WithTimeout(timeoutByValAmount(valAmount)),
		eth2http.WithPubKeyChunkSize(50),
	)
	if err != nil {
		return nil, errors.Wrap(err, "can't connect to beacon node")
	}

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, maxBeaconNodeTimeout), nil
}

// timeoutByValAmount returns the maximum timeout an eth2http call will have.
// Return a timeout of (valAmount/50)*20, where 20 are the seconds to wait.
func timeoutByValAmount(valAmount uint64) time.Duration {
	rawRate := float64(valAmount) / float64(50)
	rate := uint64(math.Ceil(rawRate))

	return time.Duration(rate*20) * time.Second
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
