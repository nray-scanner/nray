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

// ApplyDefaultTargetgeneratorCertificatetransparencyConfig sets default values for certificate transparency target generator
func ApplyDefaultTargetgeneratorCertificatetransparencyConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("enabled", false)
	defaultConfig.SetDefault("domainRegex", "^.*$")
	defaultConfig.SetDefault("tcpports", []string{"top25"})
	defaultConfig.SetDefault("udpports", []string{"top25"})
	defaultConfig.SetDefault("blacklist", []string{""})
	defaultConfig.SetDefault("maxHostsPerBatch", 150)
	defaultConfig.SetDefault("maxTcpPortsPerBatch", 25)
	defaultConfig.SetDefault("maxUdpPortsPerBatch", 25)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultTargetgeneratorLDAPConfig sets default values for ldap target generator
func ApplyDefaultTargetgeneratorLDAPConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("enabled", false)
	defaultConfig.SetDefault("ldapSearchString", "(objectCategory=computer)")
	defaultConfig.SetDefault("baseDN", "dc=contoso,dc=com")
	defaultConfig.SetDefault("ldapAttribute", "dNSHostName")
	defaultConfig.SetDefault("ldapServer", "")
	defaultConfig.SetDefault("ldapPort", 636)
	defaultConfig.SetDefault("insecure", false)
	defaultConfig.SetDefault("ldapUser", "")
	defaultConfig.SetDefault("ldapPass", "")
	defaultConfig.SetDefault("tcpports", []string{"top25"})
	defaultConfig.SetDefault("udpports", []string{"top25"})
	defaultConfig.SetDefault("blacklist", []string{""})
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
	defaultConfig.SetDefault("zgrab2.enabledModules", []string{})
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

// ApplyDefaultScannerZgrab2SSHConfig is called when Zgrab SSH is initialized
func ApplyDefaultScannerZgrab2SSHConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("subscribePorts", []string{"tcp/22"})
	defaultConfig.SetDefault("timeout", "2500ms")
	defaultConfig.SetDefault("ClientID", "SSH-2.0-Go-nray")
	// TODO: Research valid / working / useful values for cryptographic primitives
	defaultConfig.SetDefault("KexAlgorithms", "")
	defaultConfig.SetDefault("HostKeyAlgorithms", "")
	defaultConfig.SetDefault("Ciphers", "")
	defaultConfig.SetDefault("CollectUserAuth", true)
	defaultConfig.SetDefault("GexMinBits", 1024)
	defaultConfig.SetDefault("GexMaxBits", 8192)
	defaultConfig.SetDefault("GexPreferredBits", 2048)
	defaultConfig.SetDefault("Verbose", false)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}

// ApplyDefaultScannerZgrab2HTTPConfig is called when Zgrab HTTP is initialized
func ApplyDefaultScannerZgrab2HTTPConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("subscribeHTTPPorts", []string{"tcp/80", "tcp/8080", "tcp/8000"})
	defaultConfig.SetDefault("subscribeHTTPSPorts", []string{"tcp/443", "tcp/8443"})
	defaultConfig.SetDefault("timeout", "2500ms")
	defaultConfig.SetDefault("method", "GET")
	defaultConfig.SetDefault("endpoint", "/")
	defaultConfig.SetDefault("userAgent", "nray")
	defaultConfig.SetDefault("retryHTTPS", false)
	defaultConfig.SetDefault("maxSize", 256)
	defaultConfig.SetDefault("maxRedirects", 2)
	// TODO: Research valid / working / useful values for cryptographic primitives
	defaultConfig.SetDefault("heartbleed", true)
	defaultConfig.SetDefault("sessionTicket", true)
	defaultConfig.SetDefault("extendedMasterSecret", true)
	defaultConfig.SetDefault("extendedRandom", true)
	defaultConfig.SetDefault("noSNI", false)
	defaultConfig.SetDefault("sctExt", false)
	defaultConfig.SetDefault("keepClientLogs", false)
	defaultConfig.SetDefault("verifyServerCertificate", false)
	defaultConfig.SetDefault("minVersion", 0)
	defaultConfig.SetDefault("maxVersion", 0)
	defaultConfig.SetDefault("noECDHE", false)
	defaultConfig.SetDefault("heartbeatEnabled", true)
	defaultConfig.SetDefault("dsaEnabled", true)
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

// ApplyDefaultEventElasticsearchConfig is called when the ElasticsearchEventHandler is initialized
func ApplyDefaultEventElasticsearchConfig(config *viper.Viper) *viper.Viper {
	defaultConfig := viper.New()
	defaultConfig.SetDefault("useTLS", true)
	defaultConfig.SetDefault("port", 443)
	defaultConfig.SetDefault("internal.indexname", "nray")
	defaultConfig.SetDefault("internal.channelsize", 10000)
	defaultConfig.SetDefault("internal.committimer", 3)
	if config != nil {
		defaultConfig.MergeConfigMap(config.AllSettings())
	}
	return defaultConfig
}
