package utils

import (
	"time"

	"github.com/spf13/viper"
)

// ApplyDefaultConfig initializes top level configuration
// and some options that fit best here
func ApplyDefaultConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("debug", false)
	defaultConfig.SetDefault("listen", []string{"8601"})
	defaultConfig.SetDefault("host", "127.0.0.1")
	defaultConfig.SetDefault("TLS.enabled", false)
	defaultConfig.SetDefault("TLS.CA", "")
	defaultConfig.SetDefault("TLS.cert", "")
	defaultConfig.SetDefault("TLS.key", "")
	defaultConfig.SetDefault("TLS.forceClientAuth", false)
	defaultConfig.SetDefault("statusPrintInterval", 15*time.Second)
	defaultConfig.SetDefault("pools", 1)
	defaultConfig.SetDefault("considerClientPoolPreference", true)
	defaultConfig.SetDefault("internal.nodeExpiryTime", 30)
	defaultConfig.SetDefault("internal.nodeExpiryCheckInterval", 10)
	defaultConfig.SetDefault("targetgenerator.bufferSize", 5)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultTargetgeneratorStandardConfig sets default values for standard target generator
func ApplyDefaultTargetgeneratorStandardConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("enabled", false)
	defaultConfig.SetDefault("targets", []string{""})
	defaultConfig.SetDefault("targetFile", "")
	defaultConfig.SetDefault("tcpports", []string{"top25"})
	defaultConfig.SetDefault("udpports", []string{"top25"})
	defaultConfig.SetDefault("blacklist", []string{""})
	defaultConfig.SetDefault("blacklistFile", "")
	defaultConfig.SetDefault("maxHostsPerBatch", 150)
	defaultConfig.SetDefault("maxTcpPortsPerBatch", 25)
	defaultConfig.SetDefault("maxUdpPortsPerBatch", 25)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultScannerConfig is called when the node applies the configuration sent
// by the server in order to have defaults in place
func ApplyDefaultScannerConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("workers", 250)
	defaultConfig.SetDefault("ratelimit", "none")
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultScannerTCPConfig is called when the TCP scanner is initialized
func ApplyDefaultScannerTCPConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("timeout", "2500ms")
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultScannerUDPConfig is called when the UDP scanner is initialized
func ApplyDefaultScannerUDPConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("fast", false)
	defaultConfig.SetDefault("defaultHexPayload", "\x6e\x72\x61\x79") // "nray"
	defaultConfig.SetDefault("customHexPayloads", map[string]string{})
	defaultConfig.SetDefault("timeout", "2500ms")
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())

	}
	return defaultConfig
}

// ApplyDefaultEventTerminalConfig is called when the TerminalEventHandler is initialized
func ApplyDefaultEventTerminalConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("internal.channelsize", 1000)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultEventJSONFileConfig is called when the JSONFileEventHandler is initialized
func ApplyDefaultEventJSONFileConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("filename", "nray-output.json")
	defaultConfig.SetDefault("overwriteExisting", false)
	defaultConfig.SetDefault("internal.channelsize", 10000)
	defaultConfig.SetDefault("internal.synctimer", 10*time.Second)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}
