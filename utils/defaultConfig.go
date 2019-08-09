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
	createDefaultScannerConfig()
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

func createDefaultScannerConfig() {
	viper.SetDefault("scannerconfig.workers", 250)
	viper.SetDefault("scannerconfig.ratelimit", "none")
	createDefaultScannerTCPConfig()
	createDefaultScannerUDPConfig()
	createDefaultScannerZgrab2Config()
}

func createDefaultScannerTCPConfig() {
	viper.SetDefault("scannerconfig.tcp.timeout", "2500ms")
}

func createDefaultScannerUDPConfig() {
	viper.SetDefault("scannerconfig.udp.fast", false)
	viper.SetDefault("scannerconfig.udp.defaultHexPayload", "\x6e\x72\x61\x79") // "nray"
	viper.SetDefault("scannerconfig.udp.customHexPayloads", map[string]string{})
	viper.SetDefault("scannerconfig.udp.timeout", "2500ms")
}

func createDefaultScannerZgrab2Config() {
	viper.SetDefault("scannerconfig.zgrab2.enabledModules", []string{})
	createDefaultScannerZgrab2SSHConfig()
	createDefaultScannerZgrab2HTTPConfig()
}

func createDefaultScannerZgrab2SSHConfig() {
	viper.SetDefault("scannerconfig.zgrab2.ssh.subscribePorts", []string{"tcp/22"})
	viper.SetDefault("scannerconfig.zgrab2.ssh.timeout", "2500ms")
	viper.SetDefault("scannerconfig.zgrab2.ssh.ClientID", "SSH-2.0-Go-nray")
	// TODO: Research valid / working / useful values for cryptographic primitives
	viper.SetDefault("scannerconfig.zgrab2.ssh.KexAlgorithms", "")
	viper.SetDefault("scannerconfig.zgrab2.ssh.HostKeyAlgorithms", "")
	viper.SetDefault("scannerconfig.zgrab2.ssh.Ciphers", "")
	viper.SetDefault("scannerconfig.zgrab2.ssh.CollectUserAuth", true)
	viper.SetDefault("scannerconfig.zgrab2.ssh.GexMinBits", 1024)
	viper.SetDefault("scannerconfig.zgrab2.ssh.GexMaxBits", 8192)
	viper.SetDefault("scannerconfig.zgrab2.ssh.GexPreferredBits", 2048)
	viper.SetDefault("scannerconfig.zgrab2.ssh.Verbose", false)
}

func createDefaultScannerZgrab2HTTPConfig() {
	viper.SetDefault("scannerconfig.zgrab2.http.subscribeHTTPPorts", []string{"tcp/80", "tcp/8080", "tcp/8000"})
	viper.SetDefault("scannerconfig.zgrab2.http.subscribeHTTPPorts", []string{"tcp/443", "tcp/8443"})
	viper.SetDefault("scannerconfig.zgrab2.http.timeout", "2500ms")
	viper.SetDefault("scannerconfig.zgrab2.http.method", "GET")
	viper.SetDefault("scannerconfig.zgrab2.http.endpoint", "/")
	viper.SetDefault("scannerconfig.zgrab2.http.userAgent", "nray")
	viper.SetDefault("scannerconfig.zgrab2.http.retryHTTPS", false)
	viper.SetDefault("scannerconfig.zgrab2.http.maxSize", 256)
	viper.SetDefault("scannerconfig.zgrab2.http.maxRedirects", 2)
	createDefaultScannerZgrab2HTTPTlsConfig()
}

func createDefaultScannerZgrab2HTTPTlsConfig() {
	// TODO: Research valid / working / useful values for cryptographic primitives
	viper.SetDefault("scannerconfig.zgrab2.http.heartbleed", true)
	viper.SetDefault("scannerconfig.zgrab2.http.sessionTicket", true)
	viper.SetDefault("scannerconfig.zgrab2.http.extendedMasterSecret", true)
	viper.SetDefault("scannerconfig.zgrab2.http.extendedRandom", true)
	viper.SetDefault("scannerconfig.zgrab2.http.noSNI", false)
	viper.SetDefault("scannerconfig.zgrab2.http.sctExt", false)
	viper.SetDefault("scannerconfig.zgrab2.http.keepClientLogs", false)
	viper.SetDefault("scannerconfig.zgrab2.http.verifyServerCertificate", false)
	viper.SetDefault("scannerconfig.zgrab2.http.minVersion", 0)
	viper.SetDefault("scannerconfig.zgrab2.http.maxVersion", 0)
	viper.SetDefault("scannerconfig.zgrab2.http.noECDHE", false)
	viper.SetDefault("scannerconfig.zgrab2.http.heartbeatEnabled", true)
	viper.SetDefault("scannerconfig.zgrab2.http.dsaEnabled", true)
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
