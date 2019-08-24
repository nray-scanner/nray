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
	createDefaultEventConfig()

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

// CreateDefaultScannerConfig is called when the node applies the configuration sent
// by the server in order to have defaults in place
func CreateDefaultScannerConfig(config *viper.Viper) {
	config.SetDefault("workers", 250)
	config.SetDefault("ratelimit", "none")
	createDefaultScannerZgrab2Config(config)
}

// CreateDefaultScannerTCPConfig is called when the TCP scanner is initialized
func CreateDefaultScannerTCPConfig(config *viper.Viper) {
	config.SetDefault("timeout", "2500ms")
}

// CreateDefaultScannerUDPConfig is called when the UDP scanner is initialized
func CreateDefaultScannerUDPConfig(config *viper.Viper) {
	config.SetDefault("fast", false)
	config.SetDefault("defaultHexPayload", "\x6e\x72\x61\x79") // "nray"
	config.SetDefault("customHexPayloads", map[string]string{})
	config.SetDefault("timeout", "2500ms")
}

func createDefaultScannerZgrab2Config(config *viper.Viper) {
	config.SetDefault("zgrab2.enabledModules", []string{})
}

// CreateDefaultScannerZgrab2SSHConfig is called when Zgrab SSH is initialized
func CreateDefaultScannerZgrab2SSHConfig(config *viper.Viper) {
	config.SetDefault("subscribePorts", []string{"tcp/22"})
	config.SetDefault("timeout", "2500ms")
	config.SetDefault("ClientID", "SSH-2.0-Go-nray")
	// TODO: Research valid / working / useful values for cryptographic primitives
	config.SetDefault("KexAlgorithms", "")
	config.SetDefault("HostKeyAlgorithms", "")
	config.SetDefault("Ciphers", "")
	config.SetDefault("CollectUserAuth", true)
	config.SetDefault("GexMinBits", 1024)
	config.SetDefault("GexMaxBits", 8192)
	config.SetDefault("GexPreferredBits", 2048)
	config.SetDefault("Verbose", false)
}

// CreateDefaultScannerZgrab2HTTPConfig is called when Zgrab HTTP is initialized
func CreateDefaultScannerZgrab2HTTPConfig(config *viper.Viper) {
	config.SetDefault("subscribeHTTPPorts", []string{"tcp/80", "tcp/8080", "tcp/8000"})
	config.SetDefault("subscribeHTTPPorts", []string{"tcp/443", "tcp/8443"})
	config.SetDefault("timeout", "2500ms")
	config.SetDefault("method", "GET")
	config.SetDefault("endpoint", "/")
	config.SetDefault("userAgent", "nray")
	config.SetDefault("retryHTTPS", false)
	config.SetDefault("maxSize", 256)
	config.SetDefault("maxRedirects", 2)
	createDefaultScannerZgrab2HTTPTlsConfig(config)
}

func createDefaultScannerZgrab2HTTPTlsConfig(config *viper.Viper) {
	// TODO: Research valid / working / useful values for cryptographic primitives
	config.SetDefault("heartbleed", true)
	config.SetDefault("sessionTicket", true)
	config.SetDefault("extendedMasterSecret", true)
	config.SetDefault("extendedRandom", true)
	config.SetDefault("noSNI", false)
	config.SetDefault("sctExt", false)
	config.SetDefault("keepClientLogs", false)
	config.SetDefault("verifyServerCertificate", false)
	config.SetDefault("minVersion", 0)
	config.SetDefault("maxVersion", 0)
	config.SetDefault("noECDHE", false)
	config.SetDefault("heartbeatEnabled", true)
	config.SetDefault("dsaEnabled", true)
}

func createDefaultEventConfig() {
	createDefaultEventTerminalConfig()
	createDefaultEventJSONFileConfig()
	createDefaultEventElasticsearchConfig()
}

func createDefaultEventTerminalConfig() {
	viper.SetDefault("events.terminal.enabled", true)
	createDefaultEventTerminalFilterConfig()
	createDefaultEventTerminalInternalConfig()
}

func createDefaultEventTerminalFilterConfig() {
	viper.SetDefault("events.terminal.filter.environment", "")
	viper.SetDefault("events.terminal.filter.portscan.open", true)
}

func createDefaultEventTerminalInternalConfig() {
	viper.SetDefault("events.terminal.internal.channelsize", 1000)
}

func createDefaultEventJSONFileConfig() {
	viper.SetDefault("events.json-file.enabled", true)
	viper.SetDefault("events.json-file.filename", "nray-output.json")
	viper.SetDefault("events.json-file.overwriteExisting", false)
	createDefaultEventJSONFileInternalConfig()
}

func createDefaultEventJSONFileInternalConfig() {
	viper.SetDefault("events.json-file.internal.channelsize", 10000)
	viper.SetDefault("events.json-file.internal.synctimer", 10*time.Second)
}

func createDefaultEventElasticsearchConfig() {
	viper.SetDefault("events.elasticsearch.enabled", false)
	viper.SetDefault("events.elasticsearch.useTLS", true)
	viper.SetDefault("events.elasticsearch.port", 443)
	createDefaultEventElasticsearchInternalConfig()
}

func createDefaultEventElasticsearchInternalConfig() {
	viper.SetDefault("events.elasticsearch.internal.indexname", "nray")
	viper.SetDefault("events.elasticsearch.internal.channelsize", 10000)
	viper.SetDefault("events.elasticsearch.internal.committimer", 3)
}
