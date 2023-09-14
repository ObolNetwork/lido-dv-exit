// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"context"
	"os"

	"github.com/obolnetwork/charon/app/log"

	"github.com/ObolNetwork/lido-dv-exit/cmd"
)

func main() {
	ctx := context.Background()

	ctx = log.WithTopic(ctx, "cmd")

	err := cmd.Run(ctx)

	if err != nil {
		log.Error(ctx, "Fatal error", err)
		os.Exit(1)
	}
}
