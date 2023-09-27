// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"net/url"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ObolNetwork/lido-dv-exit/app"
	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
)

// Run runs lido-dv-exit.
func Run(ctx context.Context) error {
	var conf app.Config

	root := &cobra.Command{
		Use:   "lido-exit-dv",
		Short: "Validator exit tool for Lido",
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
