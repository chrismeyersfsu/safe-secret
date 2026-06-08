package main

import (
	"os"

	"github.com/chrismeyersfsu/safe-secret/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
