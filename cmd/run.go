// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	cmd.Flags().StringVar(&conf.BeaconNodeURL, "beacon-node-url", "", "URL pointing to a running ethereum beacon node.")
	cmd.Flags().StringVar(&conf.EjectorExitPath, "ejector-exit-path", "", "Filesystem path to store full exit.")
	cmd.Flags().StringVar(&conf.CharonRuntimeDir, "charon-runtime-dir", "", "Charon directory, containing the validator_keys directory and manifest file or lock file.")
	cmd.Flags().StringVar(&conf.ObolAPIURL, "obol-api-url", "https://api.obol.tech", "Obol API instance URL")

	bindLogFlags(root.Flags(), &conf.Log)

	wrapPreRunE(cmd, func(cmd *cobra.Command, args []string) error {
		if _, err := url.ParseRequestURI(conf.BeaconNodeURL); err != nil {
			return errors.New("beacon-node-url does not contain a vaild URL")
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

	if err := os.WriteFile(testFile, []byte("testfile"), 0755); err != nil {
		return errors.Wrap(err, "directory access")
	}

	if err := os.Remove(testFile); err != nil {
		return errors.Wrap(err, "testfile removal")
	}

	return nil
}
