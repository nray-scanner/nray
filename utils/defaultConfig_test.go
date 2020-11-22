package utils_test

import (
	"testing"
	"time"

	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/viper"
)

func TestApplyDefaultConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultConfig(nil)
	if !result.IsSet("debug") || result.GetBool("debug") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("listen") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("host") || result.GetString("host") != "127.0.0.1" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("TLS.enabled") || result.GetBool("TLS.enabled") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("TLS.CA") || result.GetString("TLS.CA") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("TLS.cert") || result.GetString("TLS.cert") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("TLS.key") || result.GetString("TLS.key") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("TLS.forceClientAuth") || result.GetBool("TLS.forceClientAuth") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("statusPrintInterval") || result.GetDuration("statusPrintInterval") != 15*time.Second {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("pools") || result.GetUint("pools") != 1 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("considerClientPoolPreference") || result.GetBool("considerClientPoolPreference") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.nodeExpiryTime") || result.GetUint("internal.nodeExpiryTime") != 30 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.nodeExpiryCheckInterval") || result.GetUint("internal.nodeExpiryCheckInterval") != 10 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("targetgenerator.bufferSize") || result.GetUint("targetgenerator.bufferSize") != 5 {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultConfig(emptyViper)
	if !result.IsSet("debug") || result.GetBool("debug") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("listen") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("host") || result.GetString("host") != "127.0.0.1" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("TLS.enabled") || result.GetBool("TLS.enabled") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("TLS.CA") || result.GetString("TLS.CA") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("TLS.cert") || result.GetString("TLS.cert") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("TLS.key") || result.GetString("TLS.key") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("TLS.forceClientAuth") || result.GetBool("TLS.forceClientAuth") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("statusPrintInterval") || result.GetDuration("statusPrintInterval") != 15*time.Second {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("pools") || result.GetUint("pools") != 1 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("considerClientPoolPreference") || result.GetBool("considerClientPoolPreference") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.nodeExpiryTime") || result.GetUint("internal.nodeExpiryTime") != 30 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.nodeExpiryCheckInterval") || result.GetUint("internal.nodeExpiryCheckInterval") != 10 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("targetgenerator.bufferSize") || result.GetUint("targetgenerator.bufferSize") != 5 {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("debug", true)
	viperWithValue.Set("host", "0.0.0.0")
	viperWithValue.Set("pools", 5)

	result = utils.ApplyDefaultConfig(viperWithValue)
	if !result.IsSet("debug") || result.GetBool("debug") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("listen") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("host") || result.GetString("host") != "0.0.0.0" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("TLS.enabled") || result.GetBool("TLS.enabled") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("TLS.CA") || result.GetString("TLS.CA") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("TLS.cert") || result.GetString("TLS.cert") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("TLS.key") || result.GetString("TLS.key") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("TLS.forceClientAuth") || result.GetBool("TLS.forceClientAuth") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("pools") || result.GetUint("pools") != 5 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("considerClientPoolPreference") || result.GetBool("considerClientPoolPreference") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.nodeExpiryTime") || result.GetUint("internal.nodeExpiryTime") != 30 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.nodeExpiryCheckInterval") || result.GetUint("internal.nodeExpiryCheckInterval") != 10 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("targetgenerator.bufferSize") || result.GetUint("targetgenerator.bufferSize") != 5 {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultTargetgeneratorStandardConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultTargetgeneratorStandardConfig(nil)
	if !result.IsSet("enabled") || result.GetBool("enabled") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("targets") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("targetFile") || result.GetString("targetFile") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("tcpports") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("udpports") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("blacklist") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("blacklistFile") || result.GetString("blacklistFile") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("maxHostsPerBatch") || result.GetUint("maxHostsPerBatch") != 150 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("maxTcpPortsPerBatch") || result.GetUint("maxTcpPortsPerBatch") != 25 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("maxUdpPortsPerBatch") || result.GetUint("maxUdpPortsPerBatch") != 25 {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultTargetgeneratorStandardConfig(emptyViper)
	if !result.IsSet("enabled") || result.GetBool("enabled") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("targets") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("targetFile") || result.GetString("targetFile") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("tcpports") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("udpports") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("blacklist") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("blacklistFile") || result.GetString("blacklistFile") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("maxHostsPerBatch") || result.GetUint("maxHostsPerBatch") != 150 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("maxTcpPortsPerBatch") || result.GetUint("maxTcpPortsPerBatch") != 25 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("maxUdpPortsPerBatch") || result.GetUint("maxUdpPortsPerBatch") != 25 {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("enabled", true)
	viperWithValue.Set("maxHostsPerBatch", 100)
	viperWithValue.Set("maxTcpPortsPerBatch", 50)
	viperWithValue.Set("maxUdpPortsPerBatch", 0)
	result = utils.ApplyDefaultTargetgeneratorStandardConfig(viperWithValue)
	if !result.IsSet("enabled") || result.GetBool("enabled") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("targets") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("targetFile") || result.GetString("targetFile") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("tcpports") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("udpports") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("blacklist") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("blacklistFile") || result.GetString("blacklistFile") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("maxHostsPerBatch") || result.GetUint("maxHostsPerBatch") != 100 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("maxTcpPortsPerBatch") || result.GetUint("maxTcpPortsPerBatch") != 50 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("maxUdpPortsPerBatch") || result.GetUint("maxUdpPortsPerBatch") != 0 {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultScannerConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerConfig(nil)
	if !result.IsSet("workers") || result.GetUint("workers") != 250 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("ratelimit") || result.GetString("ratelimit") != "none" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("zgrab2.enabledModules") {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerConfig(emptyViper)
	if !result.IsSet("workers") || result.GetUint("workers") != 250 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("ratelimit") || result.GetString("ratelimit") != "none" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("zgrab2.enabledModules") {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("workers", 1000)
	viperWithValue.Set("ratelimit", 25)
	result = utils.ApplyDefaultScannerConfig(viperWithValue)
	if !result.IsSet("workers") || result.GetUint("workers") != 1000 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("ratelimit") || result.GetFloat64("ratelimit") != 25 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("zgrab2.enabledModules") {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultScannerTCPConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerTCPConfig(nil)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerTCPConfig(emptyViper)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", "1500ms")
	result = utils.ApplyDefaultScannerTCPConfig(viperWithValue)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (1500*time.Millisecond) {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultScannerUDPConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerUDPConfig(nil)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("fast") || result.GetBool("fast") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("defaultHexPayload") || result.GetString("defaultHexPayload") != "\x6e\x72\x61\x79" {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerUDPConfig(emptyViper)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("fast") || result.GetBool("fast") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("defaultHexPayload") || result.GetString("defaultHexPayload") != "\x6e\x72\x61\x79" {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", "1500ms")
	viperWithValue.Set("fast", true)
	result = utils.ApplyDefaultScannerUDPConfig(viperWithValue)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (1500*time.Millisecond) {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("fast") || result.GetBool("fast") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("defaultHexPayload") || result.GetString("defaultHexPayload") != "\x6e\x72\x61\x79" {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultScannerZgrab2SSHConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerZgrab2SSHConfig(nil)
	if !result.IsSet("subscribePorts") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("ClientID") || result.GetString("ClientID") != "SSH-2.0-Go-nray" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("KexAlgorithms") || result.GetString("KexAlgorithms") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("HostKeyAlgorithms") || result.GetString("HostKeyAlgorithms") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("Ciphers") || result.GetString("Ciphers") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("CollectUserAuth") || result.GetBool("CollectUserAuth") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("GexMinBits") || result.GetUint("GexMinBits") != 1024 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("GexMaxBits") || result.GetUint("GexMaxBits") != 8192 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("GexPreferredBits") || result.GetUint("GexPreferredBits") != 2048 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("Verbose") || result.GetBool("Verbose") != false {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerZgrab2SSHConfig(emptyViper)
	if !result.IsSet("subscribePorts") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("ClientID") || result.GetString("ClientID") != "SSH-2.0-Go-nray" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("KexAlgorithms") || result.GetString("KexAlgorithms") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("HostKeyAlgorithms") || result.GetString("HostKeyAlgorithms") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("Ciphers") || result.GetString("Ciphers") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("CollectUserAuth") || result.GetBool("CollectUserAuth") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("GexMinBits") || result.GetUint("GexMinBits") != 1024 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("GexMaxBits") || result.GetUint("GexMaxBits") != 8192 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("GexPreferredBits") || result.GetUint("GexPreferredBits") != 2048 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("Verbose") || result.GetBool("Verbose") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", 400*time.Millisecond)
	viperWithValue.Set("CollectUserAuth", false)
	viperWithValue.Set("Verbose", true)

	result = utils.ApplyDefaultScannerZgrab2SSHConfig(viperWithValue)
	if !result.IsSet("subscribePorts") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 400*time.Millisecond {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("ClientID") || result.GetString("ClientID") != "SSH-2.0-Go-nray" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("KexAlgorithms") || result.GetString("KexAlgorithms") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("HostKeyAlgorithms") || result.GetString("HostKeyAlgorithms") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("Ciphers") || result.GetString("Ciphers") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("CollectUserAuth") || result.GetBool("CollectUserAuth") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("GexMinBits") || result.GetUint("GexMinBits") != 1024 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("GexMaxBits") || result.GetUint("GexMaxBits") != 8192 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("GexPreferredBits") || result.GetUint("GexPreferredBits") != 2048 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("Verbose") || result.GetBool("Verbose") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultScannerZgrab2HTTPConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerZgrab2HTTPConfig(nil)
	if !result.IsSet("subscribeHTTPPorts") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("subscribeHTTPSPorts") {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("method") || result.GetString("method") != "GET" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("endpoint") || result.GetString("endpoint") != "/" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("userAgent") || result.GetString("userAgent") != "nray" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("retryHTTPS") || result.GetBool("retryHTTPS") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("maxSize") || result.GetUint("maxSize") != 256 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("maxRedirects") || result.GetUint("maxRedirects") != 2 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("heartbleed") || result.GetBool("heartbleed") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("sessionTicket") || result.GetBool("sessionTicket") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("extendedMasterSecret") || result.GetBool("extendedMasterSecret") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("extendedRandom") || result.GetBool("extendedRandom") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("noSNI") || result.GetBool("noSNI") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("sctExt") || result.GetBool("sctExt") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("keepClientLogs") || result.GetBool("keepClientLogs") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("verifyServerCertificate") || result.GetBool("verifyServerCertificate") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("minVersion") || result.GetUint("minVersion") != 0 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("maxVersion") || result.GetUint("maxVersion") != 0 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("noECDHE") || result.GetBool("noECDHE") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("heartbeatEnabled") || result.GetBool("heartbeatEnabled") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("dsaEnabled") || result.GetBool("dsaEnabled") != true {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerZgrab2HTTPConfig(emptyViper)
	if !result.IsSet("subscribeHTTPPorts") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("subscribeHTTPSPorts") {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("method") || result.GetString("method") != "GET" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("endpoint") || result.GetString("endpoint") != "/" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("userAgent") || result.GetString("userAgent") != "nray" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("retryHTTPS") || result.GetBool("retryHTTPS") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("maxSize") || result.GetUint("maxSize") != 256 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("maxRedirects") || result.GetUint("maxRedirects") != 2 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("heartbleed") || result.GetBool("heartbleed") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("sessionTicket") || result.GetBool("sessionTicket") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("extendedMasterSecret") || result.GetBool("extendedMasterSecret") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("extendedRandom") || result.GetBool("extendedRandom") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("noSNI") || result.GetBool("noSNI") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("sctExt") || result.GetBool("sctExt") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("keepClientLogs") || result.GetBool("keepClientLogs") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("verifyServerCertificate") || result.GetBool("verifyServerCertificate") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("minVersion") || result.GetUint("minVersion") != 0 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("maxVersion") || result.GetUint("maxVersion") != 0 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("noECDHE") || result.GetBool("noECDHE") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("heartbeatEnabled") || result.GetBool("heartbeatEnabled") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("dsaEnabled") || result.GetBool("dsaEnabled") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", 1000*time.Millisecond)
	viperWithValue.Set("endpoint", "/index.php")
	viperWithValue.Set("retryHTTPS", true)
	viperWithValue.Set("heartbleed", false)
	result = utils.ApplyDefaultScannerZgrab2HTTPConfig(viperWithValue)
	if !result.IsSet("subscribeHTTPPorts") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("subscribeHTTPSPorts") {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 1000*time.Millisecond {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("method") || result.GetString("method") != "GET" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("endpoint") || result.GetString("endpoint") != "/index.php" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("userAgent") || result.GetString("userAgent") != "nray" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("retryHTTPS") || result.GetBool("retryHTTPS") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("maxSize") || result.GetUint("maxSize") != 256 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("maxRedirects") || result.GetUint("maxRedirects") != 2 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("heartbleed") || result.GetBool("heartbleed") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("sessionTicket") || result.GetBool("sessionTicket") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("extendedMasterSecret") || result.GetBool("extendedMasterSecret") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("extendedRandom") || result.GetBool("extendedRandom") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("noSNI") || result.GetBool("noSNI") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("sctExt") || result.GetBool("sctExt") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("keepClientLogs") || result.GetBool("keepClientLogs") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("verifyServerCertificate") || result.GetBool("verifyServerCertificate") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("minVersion") || result.GetUint("minVersion") != 0 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("maxVersion") || result.GetUint("maxVersion") != 0 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("noECDHE") || result.GetBool("noECDHE") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("heartbeatEnabled") || result.GetBool("heartbeatEnabled") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("dsaEnabled") || result.GetBool("dsaEnabled") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultEventTerminalConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultEventTerminalConfig(nil)
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 1000 {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultEventTerminalConfig(emptyViper)
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 1000 {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("internal.channelsize", 1500)
	result = utils.ApplyDefaultEventTerminalConfig(viperWithValue)
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 1500 {
		t.Errorf("Test failed: Passing changed value to config")
	}
}

func TestApplyDefaultEventJSONFileConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultEventJSONFileConfig(nil)
	if !result.IsSet("filename") || result.GetString("filename") != "nray-output.json" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("overwriteExisting") || result.GetBool("overwriteExisting") != false {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 10000 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.synctimer") || result.GetDuration("internal.synctimer") != 10*time.Second {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultEventJSONFileConfig(emptyViper)
	if !result.IsSet("filename") || result.GetString("filename") != "nray-output.json" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("overwriteExisting") || result.GetBool("overwriteExisting") != false {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 10000 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.synctimer") || result.GetDuration("internal.synctimer") != 10*time.Second {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("filename", "top25.json")
	viperWithValue.Set("overwriteExisting", true)
	result = utils.ApplyDefaultEventJSONFileConfig(viperWithValue)
	if !result.IsSet("filename") || result.GetString("filename") != "top25.json" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("overwriteExisting") || result.GetBool("overwriteExisting") != true {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 10000 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.synctimer") || result.GetDuration("internal.synctimer") != 10*time.Second {
		t.Errorf("Test failed: Passing changed value to config")
	}
}
