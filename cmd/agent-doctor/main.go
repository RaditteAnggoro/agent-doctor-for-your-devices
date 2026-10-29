package main

import (
	"context"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/cli"
	"os"
	"os/signal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
