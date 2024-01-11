// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/ObolNetwork/lido-dv-exit/app/keystore"
	"github.com/ObolNetwork/lido-dv-exit/app/util"
)

type bmockCliConfig struct {
	ValidatorsPubkeys []string
	LockFilePath      string
	ObolAPIBind       string
	BeaconMockBind    string

	LockFiles  []cluster.Lock
	Validators map[string]eth2v1.Validator

	Log log.Config
}

// newMockServersCmd adds the "mockservers" command to root.
func newMockServersCmd(
	root *cobra.Command,
	bnapiMock func(ctx context.Context, validators map[string]eth2v1.Validator, bindAddr string) error,
	obolAPIMock func(_ context.Context, bind string, locks []cluster.Lock, _ bool) error,
) {
	bcc := bmockCliConfig{
		Validators: map[string]eth2v1.Validator{},
	}

	cmd := &cobra.Command{
		Use:   "mockservers",
		Short: "Runs the beacon mock implementation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMockServers(cmd, bcc, bnapiMock, obolAPIMock)
		},
	}

	cmd.Flags().StringSliceVar(&bcc.ValidatorsPubkeys, "validators", []string{}, "Comma separated string containing ethereum validators public keys")
	cmd.Flags().StringVar(&bcc.BeaconMockBind, "beacon-node-bind-address", "localhost:9999", "Bind address for beacon node mock in the form of host:port")
	cmd.Flags().StringVar(&bcc.ObolAPIBind, "obol-api-bind-address", "localhost:9998", "Bind address for obol api mock in the form of host:port")
	cmd.Flags().StringVar(&bcc.LockFilePath, "lockfile-path", "", "Path for the lock file to be stored in the obol api mock")

	bindLogFlags(cmd.Flags(), &bcc.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		for idx, rawVal := range bcc.ValidatorsPubkeys {
			b, err := util.ValidatorPubkeyToBytes(rawVal)
			if err != nil {
				return errors.Wrap(err, "can't decode eth validator pubkeys")
			}

			valPubk := eth2p0.BLSPubKey(b)

			bcc.Validators[rawVal] = eth2v1.Validator{
				Index:   eth2p0.ValidatorIndex(idx + 1),
				Balance: 42,
				Status:  eth2v1.ValidatorStateActiveOngoing,
				Validator: &eth2p0.Validator{
					PublicKey:                  valPubk,
					WithdrawalCredentials:      rand32(),
					EffectiveBalance:           42,
					Slashed:                    false,
					ActivationEligibilityEpoch: 42,
					ActivationEpoch:            42,
					ExitEpoch:                  18446744073709551615,
					WithdrawableEpoch:          42,
				},
			}
		}

		userProvidedValAmt := len(bcc.Validators)

		cl, err := keystore.LoadClusterLock(filepath.Dir(bcc.LockFilePath))
		if err != nil {
			return errors.Wrap(err, "lockfile load error")
		}

		for idx, lockValidator := range cl.Validators {
			valPubk := "0x" + hex.EncodeToString(lockValidator.PublicKey)
			bcc.Validators[valPubk] = eth2v1.Validator{
				Index:   eth2p0.ValidatorIndex(idx + userProvidedValAmt + 1),
				Balance: 42,
				Status:  eth2v1.ValidatorStateActiveOngoing,
				Validator: &eth2p0.Validator{
					PublicKey:                  eth2p0.BLSPubKey(lockValidator.PublicKey),
					WithdrawalCredentials:      rand32(),
					EffectiveBalance:           42,
					Slashed:                    false,
					ActivationEligibilityEpoch: 42,
					ActivationEpoch:            42,
					ExitEpoch:                  18446744073709551615,
					WithdrawableEpoch:          42,
				},
			}
		}

		if bcc.BeaconMockBind == "" {
			return errors.New("missing beacon node mock bind address")
		}

		if bcc.ObolAPIBind == "" {
			return errors.New("missing obol api mock bind address")
		}

		fc, err := os.ReadFile(bcc.LockFilePath)
		if err != nil {
			return errors.Wrap(err, "can't read lock file")
		}

		var l cluster.Lock
		if err := json.Unmarshal(fc, &l); err != nil {
			return errors.Wrap(err, "can't unmarshal lock file")
		}

		bcc.LockFiles = append(bcc.LockFiles, l)

		return nil
	})

	root.AddCommand(cmd)
}

func runMockServers(
	cmd *cobra.Command,
	conf bmockCliConfig,
	bnapiMock func(ctx context.Context, validators map[string]eth2v1.Validator, bindAddr string) error,
	obolAPIMock func(_ context.Context, bind string, locks []cluster.Lock, _ bool) error,
) error {
	if err := log.InitLogger(conf.Log); err != nil {
		return err
	}

	log.Info(cmd.Context(), "Parsed config", flagsToLogFields(cmd.Flags())...)

	ctx := cmd.Context()

	var eg errgroup.Group

	eg.Go(func() error {
		return bnapiMock(ctx, conf.Validators, conf.BeaconMockBind)
	})

	eg.Go(func() error {
		return obolAPIMock(ctx, conf.ObolAPIBind, conf.LockFiles, false)
	})

	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "mockservers error")
	}

	return nil
}

func rand32() []byte {
	// 1:1 copy of testutil.RandomBytes32()
	var resp [32]byte
	_, _ = rand.Read(resp[:])

	return resp[:]
}
