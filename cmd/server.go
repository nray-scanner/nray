package cmd

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/nray-scanner/nray/utils"

	"github.com/nray-scanner/nray/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run as server, waiting for nodes to connect and perform a scan",
	Long: `Scanning with nodes unleashes all of nray's powers.
Perform scanning with all configuration options and multiple scanner nodes at once`,
	Run: func(cmd *cobra.Command, args []string) {
		initServerConfig()
		err := core.InitGlobalServerConfig()
		utils.CheckError(err, false)
		core.Start()
	},
}

func init() {
	//cobra.OnInitialize(initConfig)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})

	rootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	serverCmd.MarkPersistentFlagRequired("config")
}

// initConfig reads in config file and ENV variables if set.
func initServerConfig() {
	initServerDefaults()
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// We want config to be explicitly set
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.WithFields(log.Fields{
			"module": "cmd.server",
			"src":    "initServerConfig",
		}).Infof("Using config file: %s", viper.ConfigFileUsed())
	} else {
		// Debug
		utils.CheckError(err, true)
	}

}

// Default values for advanced scan are set here
func initServerDefaults() {
	log.SetFormatter(&utils.Formatter{
		HideKeys: true,
	})
	utils.CreateDefaultConfig()
}
