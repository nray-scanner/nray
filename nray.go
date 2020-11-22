package main

import (
	"fmt"

	"github.com/nray-scanner/nray/cmd"
)

// This variables can be set at build time :)
var server string
var port string
var nrayVersion = "1.2.0"

func main() {
	printMeta()
	cmd.SetHardcodedServerAndPort(server, port)
	cmd.Execute()
}

func printMeta() {
	fmt.Printf("nray %s\n", nrayVersion)
}
