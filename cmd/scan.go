package cmd

import (
	"github.com/nray-scanner/nray/utils"
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
		ports, err := utils.ParsePorts(rawPorts)
		utils.CheckError(err, false)
		targets, err := utils.ParseTargets(args)
		utils.CheckError(err, false)

		log.Infof("Scan called. Task is to scan %s on ports %v", targets, ports)
		log.Info("Well actually somebody needs to implement this first^^")
		log.Info("Til then, use the server client stuff and have a nice day")

	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&rawPorts, "ports", "p", "", "Ports to scan. A comma-separated list as well as ranges are supported.")
	scanCmd.MarkFlagRequired("ports")
}
