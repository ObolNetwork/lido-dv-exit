// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"net/url"
	"os"
	"path/filepath"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/spf13/cobra"

	"github.com/ObolNetwork/lido-dv-exit/app"
)

// newRunCmd adds the "run" command to root.
func newRunCmd(root *cobra.Command, conf app.Config, entrypoint func(ctx context.Context, config app.Config) error) {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Runs lido-dv-exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(conf.Log); err != nil {
				return err
			}

			log.Info(cmd.Context(), "Parsed config", flagsToLogFields(cmd.Flags())...)

			return entrypoint(cmd.Context(), conf)
		},
	}

	cmd.Flags().StringVarP(&conf.BeaconNodeURL, "beacon-node-url", "b", "", "URL pointing to a running ethereum beacon node.")
	cmd.Flags().StringVarP(&conf.EjectorExitPath, "ejector-exit-path", "e", "", "Filesystem path to store full exit.")
	cmd.Flags().StringVarP(&conf.CharonRuntimeDir, "charon-runtime-dir", "c", "", "Charon directory, containing the validator_keys directory and manifest file or lock file.")
	cmd.Flags().StringVarP(&conf.ObolAPIURL, "obol-api-url", "o", "https://api.obol.tech/v1", "URL pointing to an obol API instance.")
	cmd.Flags().Uint64Var(&conf.ExitEpoch, "exit-epoch", 194048, "Epoch to exit validators at.")
	cmd.Flags().IntVar(&conf.ValidatorQueryChunkSize, "validator-query-chunk-size", 50, "Chunk size for validator querying. Lower this value if you see many context timeout on validator state beacon node query.")

	bindLogFlags(cmd.Flags(), &conf.Log)
	bindLokiFlags(cmd.Flags(), &conf.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		if _, err := url.ParseRequestURI(conf.BeaconNodeURL); err != nil {
			return errors.New("beacon-node-url does not contain a vaild URL")
		}

		if conf.ValidatorQueryChunkSize <= 0 {
			return errors.New("validator query chunk size cannot be less or equal to 0")
		}

		if err := dirWritable(conf.EjectorExitPath); err != nil {
			return errors.Wrap(err, "can't access ejector exit path")
		}
		if err := dirWritable(conf.EjectorExitPath); err != nil {
			return errors.Wrap(err, "can't access ejector exit path")
		}

		if err := dirWritable(conf.CharonRuntimeDir); err != nil {
			return errors.Wrap(err, "can't access charon runtime directory")
		}

		return nil
	})

	root.AddCommand(cmd)
}

func dirWritable(dir string) error {
	testFile := filepath.Join(dir, ".test-file")

	//nolint:gosec // test file, will be deleted immediately
	if err := os.WriteFile(testFile, []byte("testfile"), 0o755); err != nil {
		return errors.Wrap(err, "directory access")
	}

	if err := os.Remove(testFile); err != nil {
		return errors.Wrap(err, "testfile removal")
	}

	return nil
}
