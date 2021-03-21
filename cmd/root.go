package cmd

import (
	"fmt"
	"os"

	"github.com/nray-scanner/nray/core"
	"github.com/spf13/cobra"
)

var cfgFile string
var nodeCmdArgs core.NodeCmdArgs

// SetHardcodedServerAndPort is a workaround to get values set by the linker into
// the namespace of the cmd package. Unfortunately setting these values directly
// for the cmd package does not work since the linker is not able to assign them
// when initializers are used, a concept cobra heavily builds on.
func SetHardcodedServerAndPort(hardcodedServer string, hardcodedPort string) {
	nodeCmdArgs = core.NodeCmdArgs{
		Server: hardcodedServer,
		Port:   hardcodedPort,
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nray",
	Short: "A modern, performant, distributed port-scanner",
	Long: `nray is port scanner written from scratch that is built
in order to get work done fast and reliably. It allows to attach 
multiple scanner nodes and to distribute work amongst them in order
to speed up scans and improve the accuracy of results.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if nodeCmdArgs.Server == "" || nodeCmdArgs.Port == "" {
			cmd.Help()
			os.Exit(1)
		}
		core.RunNode(nodeCmdArgs)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
