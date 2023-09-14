package main

import (
	"context"
	"github.com/ObolNetwork/lido-dv-exit/cmd"
	"github.com/obolnetwork/charon/app/log"
	"os"
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
