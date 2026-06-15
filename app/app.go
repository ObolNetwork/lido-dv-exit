// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/keystore"
	"github.com/ObolNetwork/lido-dv-exit/app/util"
)

// Config is the lido-dv-exit CLI configuration flag value holder.
type Config struct {
	Log                     log.Config
	BeaconNodeURL           string
	BeaconNodeHeaders       map[string]string
	EjectorExitPath         string
	CharonRuntimeDir        string
	ExitEpoch               uint64
	ObolAPIURL              string
	ValidatorQueryChunkSize int
}

const (
	maxBeaconNodeTimeout = 10 * time.Second
	obolAPITimeout       = 10 * time.Second

	// exitFilePrefix is the file name prefix of the per-validator exit files written for the
	// validator-ejector to consume: "<exitFilePrefix><validator-pubkey>.json".
	exitFilePrefix = "validator-exit-"
)

// Run runs the lido-dv-exit core logic.
func Run(ctx context.Context, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cl, keys, err := keystore.LoadManifest(ctx, config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "keystore load error")
	}

	peerID, err := keystore.PeerIDFromIdentity(config.CharonRuntimeDir)
	if err != nil {
		return errors.Wrap(err, "can't derive peer id")
	}

	// Logging labels.
	labels := map[string]string{
		"lde_cluster_hash": hex.EncodeToString(cl.LockHash),
		"lde_cluster_name": cl.Name,
		"lde_cluster_peer": p2p.PeerName(peerID),
		"lde_version":      util.GitHash(),
	}
	log.SetLokiLabels(labels)

	shareIdx, err := keystore.ShareIdxForCluster(config.CharonRuntimeDir, *cl)
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

	bnClient, err := eth2Client(
		ctx,
		config.BeaconNodeURL,
		config.BeaconNodeHeaders,
		uint64(len(valsKeys)),
		config.ValidatorQueryChunkSize,
		[4]byte(cl.ForkVersion),
	)
	if err != nil {
		return errors.Wrap(err, "can't connect to beacon node")
	}

	// Existing on-disk exits with a valid signature are skipped; ones with an invalid signature
	// are not reported as existing, so they get re-fetched and overwritten further below.
	existingValIndices, err := loadExistingValidatorExits(ctx, config.EjectorExitPath, bnClient, eth2p0.Epoch(config.ExitEpoch))
	if err != nil {
		return err
	}

	slotTicker, err := newSlotTicker(ctx, bnClient, clockwork.NewRealClock())
	if err != nil {
		return errors.Wrap(err, "can't subscribe to slot")
	}

	specResp, err := bnClient.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return errors.Wrap(err, "cannot fetch genesis spec")
	}

	rawSlotsPerEpoch, ok := specResp.Data["SLOTS_PER_EPOCH"]
	if !ok {
		return errors.Wrap(err, "spec field SLOTS_PER_EPOCH not found in spec")
	}

	slotPerEpoch, ok := rawSlotsPerEpoch.(uint64)
	if !ok {
		return errors.Wrap(err, "spec field SLOTS_PER_EPOCH is not uint64")
	}

	// define slot modulo
	// when slot % slotModulo == 0, execution of the main loop will run
	slotModulo, err := safeRand(slotPerEpoch + 1)
	if err != nil {
		return errors.Wrap(err, "can't get random number")
	}

	oAPI, err := obolapi.New(config.ObolAPIURL)
	if err != nil {
		return errors.Wrap(err, "cannot create Obol API client")
	}

	var signedExits []obolapi.ExitBlob

	fetchedSignedExits := map[string]struct{}{}

	for slot := range slotTicker {
		if len(valsKeys) == 0 {
			// if we don't have any more keys to process, make sure we fetched *all* full exits before
			// exiting this loop
			if len(fetchedSignedExits) != len(signedExits) {
				writeAllFullExits(
					ctx,
					oAPI,
					cl,
					signedExits,
					fetchedSignedExits,
					config.EjectorExitPath,
					shareIdx,
					identityKey,
					bnClient,
					eth2p0.Epoch(config.ExitEpoch),
				)

				continue
			}

			break // we finished signing everything we had to sign
		}

		if slot.Slot%slotModulo != 0 {
			log.Debug(
				ctx,
				"Slot not in modulo",
				z.U64("epoch", slot.Epoch()),
				z.U64("modulo", slotModulo),
				z.U64("slot", slot.Slot),
			)

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
			exit, err := signExit(
				ctx,
				valIndex,
				valKeyShare.Share,
				bnClient,
				eth2p0.Epoch(config.ExitEpoch),
			)
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
			err := postPartialExit(ctx, oAPI, cl.LockHash, shareIdx, identityKey, signedExitsInRound...)
			if err != nil {
				log.Error(ctx, "Cannot post exits to obol api, will retry later", err)
			} else {
				for _, signedExit := range signedExitsInRound {
					delete(valsKeys, keystore.ValidatorPubkey(signedExit.PublicKey))
				}
			}

			signedExits = append(signedExits, signedExitsInRound...)
		}

		writeAllFullExits(
			ctx,
			oAPI,
			cl,
			signedExits,
			fetchedSignedExits,
			config.EjectorExitPath,
			shareIdx,
			identityKey,
			bnClient,
			eth2p0.Epoch(config.ExitEpoch),
		)
	}

	log.Info(ctx, "Successfully fetched exit messages!")

	return nil
}

// writeAllFullExits fetches and writes signedExits to disk.
func writeAllFullExits(
	ctx context.Context,
	oAPI obolapi.Client,
	cl *cluster.Lock,
	signedExits []obolapi.ExitBlob,
	alreadySignedExits map[string]struct{},
	ejectorExitPath string,
	shareIndex uint64,
	identityKey *k1.PrivateKey,
	eth2Cl eth2wrap.Client,
	epoch eth2p0.Epoch,
) {
	for _, signedExit := range signedExits {
		if _, ok := alreadySignedExits[signedExit.PublicKey]; ok {
			continue // bypass already-fetched full exit
		}

		partialPubKeys, err := pubSharesForValidator(cl, signedExit.PublicKey)
		if err != nil {
			log.Error(ctx, "Cannot find public shares for validator", err, z.Str("validator", signedExit.PublicKey))
			continue
		}

		exitFSPath := filepath.Join(ejectorExitPath, fmt.Sprintf("%s%s.json", exitFilePrefix, signedExit.PublicKey))

		if !fetchFullExit(
			ctx,
			oAPI,
			cl.LockHash,
			signedExit.PublicKey,
			exitFSPath,
			shareIndex,
			identityKey,
			eth2Cl,
			epoch,
			partialPubKeys,
		) {
			log.Debug(ctx, "Could not fetch full exit for validator", z.Str("validator", signedExit.PublicKey))
			continue
		}

		alreadySignedExits[signedExit.PublicKey] = struct{}{}
	}
}

// pubSharesForValidator returns the partial public shares for the validator identified by
// validatorPubkey, as found in the cluster lock.
func pubSharesForValidator(cl *cluster.Lock, validatorPubkey string) ([][]byte, error) {
	for _, val := range cl.Validators {
		if strings.EqualFold(val.PublicKeyHex(), validatorPubkey) {
			return val.PubShares, nil
		}
	}

	return nil, errors.New("validator public key not found in cluster lock", z.Str("validator", validatorPubkey))
}

// fetchFullExit returns true if a full exit was received from the Obol API, and was written in exitFSPath.
// Each HTTP request has a default timeout.
func fetchFullExit(
	ctx context.Context,
	oAPI obolapi.Client,
	lockHash []byte,
	validatorPubkey, exitFSPath string,
	shareIndex uint64,
	identityKey *k1.PrivateKey,
	eth2Cl eth2wrap.Client,
	epoch eth2p0.Epoch,
	partialPubKeys [][]byte,
) bool {
	ctx, cancel := context.WithTimeout(ctx, obolAPITimeout)
	defer cancel()

	fullExit, err := oAPI.GetFullExit(ctx, validatorPubkey, lockHash, shareIndex, identityKey, partialPubKeys, eth2Cl)
	if err != nil {
		if !errors.Is(err, obolapi.ErrNoValue) {
			log.Warn(ctx, "Cannot fetch full exit from obol api, will retry", err)
		}

		return false
	}

	data, err := fullExit.SignedExitMessage.MarshalJSON()
	if err != nil {
		log.Warn(ctx, "Cannot marshal exit to json", err)

		return false
	}

	err = verifyFullExit(ctx, validatorPubkey, fullExit.SignedExitMessage, eth2Cl, epoch)
	if err != nil {
		log.Error(ctx, "Exit message signature not verified", err)

		return false
	}

	//nolint:gosec // must be wide open
	err = os.WriteFile(exitFSPath, data, 0o755)
	if err != nil {
		log.Warn(ctx, "Cannot write exit to filesystem path", err, z.Str("destination_path", exitFSPath))
		return false
	}

	return true
}

// verifyFullExit verifies that signedExit is a voluntary exit message validly signed by the
// validator's aggregate public key (validatorPubkey) at the given exit epoch.
func verifyFullExit(ctx context.Context, validatorPubkey string, signedExit eth2p0.SignedVoluntaryExit, eth2Cl eth2wrap.Client, epoch eth2p0.Epoch) error {
	rawPkBytes, err := util.ValidatorPubkeyToBytes(validatorPubkey)
	if err != nil {
		return errors.Wrap(err, "decode validator public key")
	}

	pubkey, err := tblsconv.PubkeyFromBytes(rawPkBytes)
	if err != nil {
		return errors.Wrap(err, "convert public key to tbls type")
	}

	signature, err := tblsconv.SignatureFromBytes(signedExit.Signature[:])
	if err != nil {
		return errors.Wrap(err, "convert signature to tbls type")
	}

	exitRoot, err := sigDataForExit(ctx, *signedExit.Message, eth2Cl, epoch)
	if err != nil {
		return errors.Wrap(err, "calculate hash tree root for exit message")
	}

	err = tbls.Verify(pubkey, exitRoot[:], signature)
	if err != nil {
		return errors.Wrap(err, "exit message signature verification")
	}

	return nil
}

// postPartialExit posts exitBlobs to Obol API with a default HTTP request timeout.
func postPartialExit(ctx context.Context, oAPI obolapi.Client, mutationHash []byte, shareIndex uint64, identityKey *k1.PrivateKey, exitBlobs ...obolapi.ExitBlob) error {
	ctx, cancel := context.WithTimeout(ctx, obolAPITimeout)
	defer cancel()

	err := oAPI.PostPartialExits(ctx, mutationHash, shareIndex, identityKey, exitBlobs...)
	if err != nil {
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
func signExit(
	ctx context.Context,
	valIdx eth2p0.ValidatorIndex,
	keyShare tbls.PrivateKey,
	eth2Cl eth2wrap.Client,
	exitEpoch eth2p0.Epoch,
) (eth2p0.SignedVoluntaryExit, error) {
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
func eth2Client(
	ctx context.Context,
	bnURL string,
	bnHeaders map[string]string,
	valAmount uint64,
	chunkSize int,
	forkVersion [4]byte,
) (eth2wrap.Client, error) {
	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(1), // zerolog.InfoLevel
		eth2http.WithTimeout(timeoutByValAmount(valAmount)),
		eth2http.WithPubKeyChunkSize(chunkSize),
	)
	if err != nil {
		return nil, errors.Wrap(err, "can't connect to beacon node")
	}

	bnClient := eth2wrap.AdaptEth2HTTP(bnHTTPClient.(*eth2http.Service), bnHeaders, maxBeaconNodeTimeout)
	bnClient.SetForkVersion(forkVersion)

	return bnClient, nil
}

// timeoutByValAmount returns the maximum timeout an eth2http call will have.
// Return a timeout of (valAmount/50)*20, where 20 are the seconds to wait.
func timeoutByValAmount(valAmount uint64) time.Duration {
	rawRate := float64(valAmount) / float64(50)
	rate := uint64(math.Ceil(rawRate))

	return time.Duration(rate*20) * time.Second
}

// loadExistingValidatorExits reads the indices for validators whose exits have already been
// processed. An exit is only considered already-processed if its on-disk signature verifies;
// exits with an invalid signature are skipped (and logged), so they get re-fetched and overwritten.
func loadExistingValidatorExits(ctx context.Context, ejectorPath string, eth2Cl eth2wrap.Client, epoch eth2p0.Epoch) (map[eth2p0.ValidatorIndex]struct{}, error) {
	exitPaths, err := filepath.Glob(filepath.Join(ejectorPath, "*.json"))
	if err != nil {
		return nil, errors.Wrap(err, "ejector exits glob")
	}

	ret := map[eth2p0.ValidatorIndex]struct{}{}

	for _, ep := range exitPaths {
		exitBytes, err := os.ReadFile(ep)
		if err != nil {
			return nil, errors.Wrap(err, "read exit file", z.Str("path", ep))
		}

		var exit eth2p0.SignedVoluntaryExit

		err = json.Unmarshal(exitBytes, &exit)
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal exit file", z.Str("path", ep))
		}

		validatorPubkey, err := validatorPubkeyFromExitPath(ep)
		if err != nil {
			return nil, errors.Wrap(err, "validator pubkey from exit file name", z.Str("path", ep))
		}

		err = verifyFullExit(ctx, validatorPubkey, exit, eth2Cl, epoch)
		if err != nil {
			log.Warn(ctx, "Incorrect exit signature, re-fetching", err,
				z.Str("path", ep),
				z.U64("validx", uint64(exit.Message.ValidatorIndex)),
			)

			continue
		}

		ret[exit.Message.ValidatorIndex] = struct{}{}
	}

	return ret, nil
}

// validatorPubkeyFromExitPath extracts the validator public key from an exit file path of the
// form "<exitFilePrefix><pubkey>.json".
func validatorPubkeyFromExitPath(exitPath string) (string, error) {
	base := filepath.Base(exitPath)

	if !strings.HasPrefix(base, exitFilePrefix) || !strings.HasSuffix(base, ".json") {
		return "", errors.New("unexpected exit file name", z.Str("filename", base))
	}

	pubkey := strings.TrimSuffix(strings.TrimPrefix(base, exitFilePrefix), ".json")
	if pubkey == "" {
		return "", errors.New("empty validator pubkey in exit file name", z.Str("filename", base))
	}

	return pubkey, nil
}

// safeRand returns a random uint64 from 1 to max, using crypto/rand as a source.
func safeRand(maxRand uint64) (uint64, error) {
	bigMax := big.NewInt(int64(maxRand))
	zero := big.NewInt(0)

	for {
		candidate, err := rand.Int(rand.Reader, bigMax)
		if err != nil {
			//nolint:wrapcheck // will wrap in outer field
			return 0, err
		}

		//	-1 if x <  y
		//	 0 if x == y
		//	+1 if x >  y
		if candidate.Cmp(zero) == 1 {
			return candidate.Uint64(), nil
		}
	}
}
