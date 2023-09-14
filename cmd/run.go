package cmd

import (
	"context"
	"github.com/ObolNetwork/lido-dv-exit/app"
	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/spf13/cobra"
	"net/url"
	"os"
	"path/filepath"
)

// Run runs lido-dv-exit.
func Run(ctx context.Context) error {
	return New(app.Run).ExecuteContext(ctx)
}

// New returns a new root cobra command that executes lido-dv-exit.
func New(entrypoint func(ctx context.Context, config app.Config) error) *cobra.Command {
	var conf app.Config

	root := &cobra.Command{
		Use:   "lido-exit-dv",
		Short: "Validator exit tool for Lido",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := log.InitLogger(conf.Log); err != nil {
				return err
			}
			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			log.Info(cmd.Context(), "Parsed config", flagsToLogFields(cmd.Flags())...)

			return entrypoint(cmd.Context(), conf)
		},
	}

	bindLogFlags(root.Flags(), &conf.Log)

	root.Flags().StringVar(&conf.BeaconNodeURL, "beacon-node-url", "", "URL pointing to a running beacon node")
	root.Flags().StringVar(&conf.EjectorExitPath, "ejector-exit-path", "", "Filesystem path to store full exit.")
	root.Flags().StringVar(&conf.CharonRuntimeDir, "charon-runtime-dir", "", "Charon directory, containing the validator_keys directory and manifest file or lock file.")

	wrapPreRunE(root, func(cmd *cobra.Command, args []string) error {
		if _, err := url.ParseRequestURI(conf.BeaconNodeURL); err != nil {
			return errors.New("beacon-node-url does not contain a vaild URL")
		}

		if err := dirWritable(conf.EjectorExitPath); err != nil {
			return errors.Wrap(err, "can't access ejector exit path")
		}

		if err := dirWritable(conf.CharonRuntimeDir); err != nil {
			return errors.Wrap(err, "can't access charon runtime directory")
		}

		return nil
	})

	return root
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
