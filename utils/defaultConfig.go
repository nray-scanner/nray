package utils

import (
	"time"

	"github.com/spf13/viper"
)

// CreateDefaultConfig is the place where all default config values
// are defined and initialized
// Each sublevel of configuration should initialized in its own function
func CreateDefaultConfig() {
	viper.SetDefault("debug", false)
	viper.SetDefault("listen", []string{"8601"})
	viper.SetDefault("host", "127.0.0.1")
	createDefaultTLSConfig()
	viper.SetDefault("pools", 1)
	viper.SetDefault("considerClientPoolPreference", true)
	createDefaultInternalConfig()
	createDefaultTargetgeneratorConfig()

}

func createDefaultTLSConfig() {
	viper.SetDefault("TLS.enabled", false)
	viper.SetDefault("TLS.CA", "")
	viper.SetDefault("TLS.cert", "")
	viper.SetDefault("TLS.key", "")
	viper.SetDefault("TLS.forceClientAuth", false)
}

func createDefaultInternalConfig() {
	viper.SetDefault("internal.nodeExpiryTime", 30)
	viper.SetDefault("internal.nodeExpiryCheckInterval", 10)
}

func createDefaultTargetgeneratorConfig() {
	viper.SetDefault("targetgenerator.bufferSize", 5)
	createDefaultTargetgeneratorStandardConfig()
	createDefaultTargetgeneratorCertificatetransparencyConfig()
	createDefaultTargetgeneratorLDAPConfig()
}

func createDefaultTargetgeneratorStandardConfig() {
	viper.SetDefault("standard.enabled", false)
	viper.SetDefault("standard.targets", []string{""})
	viper.SetDefault("standard.targetFile", "")
	viper.SetDefault("standard.tcpports", []string{"top25"})
	viper.SetDefault("standard.udpports", []string{"top25"})
	viper.SetDefault("standard.blacklist", []string{""})
	viper.SetDefault("standard.blacklistFile", "")
	viper.SetDefault("standard.maxHostsPerBatch", 150)
	viper.SetDefault("standard.maxTcpPortsPerBatch", 25)
	viper.SetDefault("standard.maxUdpPortsPerBatch", 25)
}

func createDefaultTargetgeneratorCertificatetransparencyConfig() {
	viper.SetDefault("certificatetransparency.enabled", false)
	viper.SetDefault("certificatetransparency.domainRegex", "^.*$")
	viper.SetDefault("certificatetransparency.tcpports", []string{"top25"})
	viper.SetDefault("certificatetransparency.udpports", []string{"top25"})
	viper.SetDefault("certificatetransparency.blacklist", []string{""})
	viper.SetDefault("certificatetransparency.maxHostsPerBatch", 150)
	viper.SetDefault("certificatetransparency.maxTcpPortsPerBatch", 25)
	viper.SetDefault("certificatetransparency.maxUdpPortsPerBatch", 25)
}

func createDefaultTargetgeneratorLDAPConfig() {
	viper.SetDefault("ldap.enabled", false)
	viper.SetDefault("ldap.ldapSearchString", "(objectCategory=computer)")
	viper.SetDefault("ldap.baseDN", "dc=contoso,dc=com")
	viper.SetDefault("ldap.ldapAttribute", "dNSHostName")
	viper.SetDefault("ldap.ldapServer", "")
	viper.SetDefault("ldap.ldapPort", 636)
	viper.SetDefault("ldap.insecure", false)
	viper.SetDefault("ldap.ldapUser", "")
	viper.SetDefault("ldap.ldapPass", "")
	viper.SetDefault("ldap.tcpports", []string{"top25"})
	viper.SetDefault("ldap.udpports", []string{"top25"})
	viper.SetDefault("ldap.blacklist", []string{""})
	viper.SetDefault("ldap.maxHostsPerBatch", 5)
	viper.SetDefault("ldap.maxTcpPortsPerBatch", 25)
	viper.SetDefault("ldap.maxUdpPortsPerBatch", 25)
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
	defaultConfig.SetDefault("filter.environment", "")
	defaultConfig.SetDefault("filter.portscan.open", true)
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
