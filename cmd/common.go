// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/ObolNetwork/lido-dv-exit/app"
	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
)

const (
	lidoDVExit = "lidodvexit"
)

// Run runs lido-dv-exit.
func Run(ctx context.Context) error {
	var conf app.Config

	root := &cobra.Command{
		Use:   "lido-exit-dv",
		Short: "Validator exit tool for Lido",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return initializeConfig(cmd)
		},
	}

	newRunCmd(root, conf, app.Run)
	newMockServersCmd(root, bnapi.Run, obolapi.Run)
	newVersionCmd(root)

	return root.ExecuteContext(ctx)
}

// flagsToLogFields converts the given flags to log fields.
func flagsToLogFields(flags *pflag.FlagSet) []z.Field {
	var fields []z.Field
	flags.VisitAll(func(flag *pflag.Flag) {
		val := redact(flag.Name, flag.Value.String())

		if sliceVal, ok := flag.Value.(pflag.SliceValue); ok {
			var vals []string
			for _, s := range sliceVal.GetSlice() {
				vals = append(vals, redact(flag.Name, s))
			}
			val = "[" + strings.Join(vals, ",") + "]"
		}

		fields = append(fields, z.Str(flag.Name, val))
	})

	return fields
}

// redact returns a redacted version of the given flag value. It currently supports redacting
// passwords in valid URLs provided in ".*address.*" flags and redacting auth tokens.
func redact(flag, val string) string {
	if strings.Contains(flag, "auth-token") {
		return "xxxxx"
	}

	if !strings.Contains(flag, "address") {
		return val
	}

	u, err := url.Parse(val)
	if err != nil {
		return val
	}

	return u.Redacted()
}

func bindLogFlags(flags *pflag.FlagSet, config *log.Config) {
	flags.StringVar(&config.Format, "log-format", "console", "Log format; console, logfmt or json")
	flags.StringVar(&config.Level, "log-level", "info", "Log level; debug, info, warn or error")
	flags.StringVar(&config.Color, "log-color", "auto", "Log color; auto, force, disable.")
}

// wrapPreRunE wraps the provided preRunE function.
func wrapPreRunE(cmd *cobra.Command, fn func(cmd *cobra.Command, args []string) error) {
	preRunE := cmd.PreRunE // Allow multiple wraps of PreRunE.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		err := fn(cmd, args)
		if err != nil {
			return err
		}

		if preRunE != nil {
			return preRunE(cmd, args)
		}

		return nil
	}
}

// initializeConfig sets up the general viper config and binds the cobra flags to the viper flags.
func initializeConfig(cmd *cobra.Command) error {
	v := viper.New()

	v.SetConfigName(lidoDvExit)
	v.AddConfigPath(".")

	// Attempt to read the config file, gracefully ignoring errors
	// caused by a config file not being found. Return an error
	// if we cannot parse the config file.
	if err := v.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		var cfgError viper.ConfigFileNotFoundError
		if ok := errors.As(err, &cfgError); !ok {
			return errors.Wrap(err, "read config")
		}
	}

	v.SetEnvPrefix(lidoDvExit)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Bind the current command's flags to viper
	return bindFlags(cmd, v)
}

// bindFlags binds each cobra flag to its associated viper configuration (config file and environment variable).
func bindFlags(cmd *cobra.Command, v *viper.Viper) error {
	var lastErr error

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Cobra provided flags take priority
		if f.Changed {
			return
		}

		// Define all the viper flag names to check
		viperNames := []string{
			f.Name,
			strings.ReplaceAll(f.Name, "_", "."), // TOML uses "." to indicate hierarchy, while we use "_" in this example.
		}

		for _, name := range viperNames {
			if !v.IsSet(name) {
				continue
			}

			val := v.Get(name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				lastErr = err
			}

			break
		}
	})

	return lastErr
}
