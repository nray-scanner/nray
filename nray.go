package main

import (
	"fmt"

	"github.com/nray-scanner/nray/cmd"
)

// This variables can be set at build time :)
var server string
var port string

// These are set by goreleaser
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	printMeta()
	cmd.SetHardcodedServerAndPort(server, port)
	cmd.Execute()
}

func printMeta() {
	fmt.Printf("nray %s\nBuilt on %s from commit %s\n", version, date, commit)
}
