package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rawPorts string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Starts a scan with parameters provided on the command line",
	Long: `If you want to initiate a quick and dirty simple scan without 
creating a configuration and attaching scanner nodes, the simple scan
is what you are looking for. Get the work done nmap-style like you are used to.`,
	Run: func(cmd *cobra.Command, args []string) {

		log.Info("Well actually somebody needs to implement this first...")
		log.Info("Until then, please use the server/client functionality and have a nice day")

	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&rawPorts, "ports", "p", "", "Ports to scan. A comma-separated list as well as ranges are supported.")
	scanCmd.MarkFlagRequired("ports")
}
