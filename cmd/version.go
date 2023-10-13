// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// newVersionCmd adds the "version" command to root.
func newVersionCmd(root *cobra.Command) {
	var fullVersion bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Returns lido-dv-exit version information",
		RunE: func(_ *cobra.Command, __ []string) error {
			raw, _ := debug.ReadBuildInfo()

			info := vcsInfoMap(raw)

			if !fullVersion {
				fmt.Println(info["vcs.revision"]) //nolint:forbidigo // printing version
				return nil
			}

			fmt.Println("lido-dv-exit") //nolint:forbidigo // printing version

			for k, v := range info {
				fmt.Printf("%s: %s\n", k, v) //nolint:forbidigo // printing version
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&fullVersion, "full", false, "Print full version information.")

	root.AddCommand(cmd)
}

// vcsInfoMap gets vcs information from bi and returns them as a map[string]string.
func vcsInfoMap(bi *debug.BuildInfo) map[string]string {
	ret := map[string]string{
		"vcs.revision": "",
		"vcs.time":     "",
		"vcs.modified": "",
	}

	for _, element := range bi.Settings {
		if _, ok := ret[element.Key]; ok {
			ret[element.Key] = element.Value
		}
	}

	return ret
}
