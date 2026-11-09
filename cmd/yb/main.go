package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/trcli"
)

func main() {
	if err := trcli.RootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "tr: %v\n", err)
		os.Exit(exitCode(err))
	}
}

func exitCode(err error) int {
	var exit *cictx.ExitError
	if errors.As(err, &exit) && exit.Code != 0 {
		return exit.Code
	}
	var child *trcli.ChildExit
	if errors.As(err, &child) && child.Code != 0 {
		return child.Code
	}
	return 1
}
