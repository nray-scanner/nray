package utils_test

import (
	"testing"
	"time"

	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/viper"
)

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
	if !result.IsSet("filter.environment") || result.GetString("filter.environment") != "" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("filter.portscan.open") || result.GetBool("filter.portscan.open") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 1000 {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultEventTerminalConfig(emptyViper)
	if !result.IsSet("filter.environment") || result.GetString("filter.environment") != "" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("filter.portscan.open") || result.GetBool("filter.portscan.open") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 1000 {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("filter.portscan.open", false)
	viperWithValue.Set("internal.channelsize", 1500)
	result = utils.ApplyDefaultEventTerminalConfig(viperWithValue)
	if !result.IsSet("filter.environment") || result.GetString("filter.environment") != "" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("filter.portscan.open") || result.GetBool("filter.portscan.open") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
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

func TestDefaultEventElasticsearchConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultEventElasticsearchConfig(nil)
	if !result.IsSet("useTLS") || result.GetBool("useTLS") != true {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("port") || result.GetUint("port") != 443 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.indexname") || result.GetString("internal.indexname") != "nray" {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 10000 {
		t.Errorf("Test failed: Passing nil to config")
	}
	if !result.IsSet("internal.committimer") || result.GetUint("internal.committimer") != 3 {
		t.Errorf("Test failed: Passing nil to config")
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultEventElasticsearchConfig(emptyViper)
	if !result.IsSet("useTLS") || result.GetBool("useTLS") != true {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("port") || result.GetUint("port") != 443 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.indexname") || result.GetString("internal.indexname") != "nray" {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 10000 {
		t.Errorf("Test failed: Passing empty viper to config")
	}
	if !result.IsSet("internal.committimer") || result.GetUint("internal.committimer") != 3 {
		t.Errorf("Test failed: Passing empty viper to config")
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("useTLS", false)
	viperWithValue.Set("port", 8443)
	result = utils.ApplyDefaultEventElasticsearchConfig(viperWithValue)
	if !result.IsSet("useTLS") || result.GetBool("useTLS") != false {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("port") || result.GetUint("port") != 8443 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.indexname") || result.GetString("internal.indexname") != "nray" {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.channelsize") || result.GetUint("internal.channelsize") != 10000 {
		t.Errorf("Test failed: Passing changed value to config")
	}
	if !result.IsSet("internal.committimer") || result.GetUint("internal.committimer") != 3 {
		t.Errorf("Test failed: Passing changed value to config")
	}
}
