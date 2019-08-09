package cmd

import (
	"github.com/nray-scanner/nray/core"
	"github.com/spf13/cobra"
)

// These are required, otherwise cobra's default initializers overwrite values passed at compile time

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "node is the scanner node component that joins a scanning fleet controlled by an upstream server.",
	Long: `The nray node connects to a upstream nray server and performs network discovery
scans on behalf of the server. For itself, it is useless.`,
	Run: func(cmd *cobra.Command, args []string) {
		core.RunNode(nodeCmdArgs)
	},
}

// Get configuration from command line
func parseCmdLine() {
	nodeCmd.PersistentFlags().BoolVar(&nodeCmdArgs.Debug, "debug", false, "Enable debug output")

	nodeCmd.PersistentFlags().StringVarP(&nodeCmdArgs.Server, "server", "s", "",
		"upstream nray server address")
	nodeCmd.PersistentFlags().StringVarP(&nodeCmdArgs.Port, "port", "p", "",
		"upstream nray server port")
	nodeCmd.PersistentFlags().Int32Var(&nodeCmdArgs.PreferredPool, "preferred-pool", -1,
		"Pool to be preferably placed in at the server. If configured, the server respects this as long as the pool exists")
	nodeCmd.PersistentFlags().StringVar(&nodeCmdArgs.NodeName, "node-name", "",
		"Assign a name to this scanning node. Useful if you are running multiple nodes and want to distinguish results.")
	nodeCmd.PersistentFlags().BoolVar(&nodeCmdArgs.UseTLS, "use-tls", false, "Set true to use TLS")
	nodeCmd.PersistentFlags().BoolVar(&nodeCmdArgs.TLSIgnoreServerCertificate, "tls-insecure",
		false, "Literally. Trust anybody. Requires --use-tls")
	nodeCmd.PersistentFlags().StringVar(&nodeCmdArgs.TLSCACertPath, "tls-ca-cert", "",
		"path to ca certificate if TLS is used. Requires --use-tls")
	nodeCmd.PersistentFlags().StringVar(&nodeCmdArgs.TLSClientKeyPath, "tls-client-key", "",
		"path to tls client key. Requires --use-tls")
	nodeCmd.PersistentFlags().StringVar(&nodeCmdArgs.TLSClientCertPath, "tls-client-cert", "",
		"path to tls client cert. Requires --use-tls")
	nodeCmd.PersistentFlags().StringVar(&nodeCmdArgs.TLSServerSAN, "tls-server-SAN", "",
		"subject alternative name of the server. Go's TLS implementation checks this value against the values provided in the certificate and refuses to connect if no match is found")

}

func init() {
	rootCmd.AddCommand(nodeCmd)
	parseCmdLine()
}
