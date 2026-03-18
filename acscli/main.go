package main

import (
	"os"

	"github.com/stackrox/rox/acscli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
