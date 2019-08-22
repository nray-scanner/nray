package main

import (
	"fmt"

	"github.com/nray-scanner/nray/cmd"
)

// This variables can be set at build time :)
var server string
var port string
var nrayVersion = "1.0.1"

func main() {
	printMeta()
	cmd.SetHardcodedServerAndPort(server, port)
	cmd.Execute()
}

func printMeta() {
	fmt.Printf("nray distributed network scanner, version %s\n", nrayVersion)
	fmt.Printf("By Michael Eder, https://twitter.com/michael_eder_\n")
	fmt.Printf("Documentation: https://nray-scanner.org\n\n")
}
