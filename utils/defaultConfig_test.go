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
		t.Fail()
	}
	if !result.IsSet("ratelimit") || result.GetString("ratelimit") != "none" {
		t.Fail()
	}
	if !result.IsSet("zgrab2.enabledModules") {
		t.Fail()
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerConfig(emptyViper)
	if !result.IsSet("workers") || result.GetUint("workers") != 250 {
		t.Fail()
	}
	if !result.IsSet("ratelimit") || result.GetString("ratelimit") != "none" {
		t.Fail()
	}
	if !result.IsSet("zgrab2.enabledModules") {
		t.Fail()
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("workers", 1000)
	viperWithValue.Set("ratelimit", 25)
	result = utils.ApplyDefaultScannerConfig(viperWithValue)
	if !result.IsSet("workers") || result.GetUint("workers") != 1000 {
		t.Fail()
	}
	if !result.IsSet("ratelimit") || result.GetFloat64("ratelimit") != 25 {
		t.Fail()
	}
	if !result.IsSet("zgrab2.enabledModules") {
		t.Fail()
	}
}

func TestApplyDefaultScannerTCPConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerTCPConfig(nil)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Fail()
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerTCPConfig(emptyViper)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Fail()
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", "1500ms")
	result = utils.ApplyDefaultScannerTCPConfig(viperWithValue)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (1500*time.Millisecond) {
		t.Fail()
	}
}

func TestApplyDefaultScannerUDPConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerUDPConfig(nil)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Fail()
	}
	if !result.IsSet("fast") || result.GetBool("fast") != false {
		t.Fail()
	}
	if !result.IsSet("defaultHexPayload") || result.GetString("defaultHexPayload") != "\x6e\x72\x61\x79" {
		t.Fail()
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerUDPConfig(emptyViper)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (2500*time.Millisecond) {
		t.Fail()
	}
	if !result.IsSet("fast") || result.GetBool("fast") != false {
		t.Fail()
	}
	if !result.IsSet("defaultHexPayload") || result.GetString("defaultHexPayload") != "\x6e\x72\x61\x79" {
		t.Fail()
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", "1500ms")
	viperWithValue.Set("fast", true)
	result = utils.ApplyDefaultScannerUDPConfig(viperWithValue)
	if !result.IsSet("timeout") || result.GetDuration("timeout") != (1500*time.Millisecond) {
		t.Fail()
	}
	if !result.IsSet("fast") || result.GetBool("fast") != true {
		t.Fail()
	}
	if !result.IsSet("defaultHexPayload") || result.GetString("defaultHexPayload") != "\x6e\x72\x61\x79" {
		t.Fail()
	}
}

func TestApplyDefaultScannerZgrab2SSHConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerZgrab2SSHConfig(nil)
	if !result.IsSet("subscribePorts") {
		t.Fail()
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Fail()
	}
	if !result.IsSet("ClientID") || result.GetString("ClientID") != "SSH-2.0-Go-nray" {
		t.Fail()
	}
	if !result.IsSet("KexAlgorithms") || result.GetString("KexAlgorithms") != "" {
		t.Fail()
	}
	if !result.IsSet("HostKeyAlgorithms") || result.GetString("HostKeyAlgorithms") != "" {
		t.Fail()
	}
	if !result.IsSet("Ciphers") || result.GetString("Ciphers") != "" {
		t.Fail()
	}
	if !result.IsSet("CollectUserAuth") || result.GetBool("CollectUserAuth") != true {
		t.Fail()
	}
	if !result.IsSet("GexMinBits") || result.GetUint("GexMinBits") != 1024 {
		t.Fail()
	}
	if !result.IsSet("GexMaxBits") || result.GetUint("GexMaxBits") != 8192 {
		t.Fail()
	}
	if !result.IsSet("GexPreferredBits") || result.GetUint("GexPreferredBits") != 2048 {
		t.Fail()
	}
	if !result.IsSet("Verbose") || result.GetBool("Verbose") != false {
		t.Fail()
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerZgrab2SSHConfig(emptyViper)
	if !result.IsSet("subscribePorts") {
		t.Fail()
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Fail()
	}
	if !result.IsSet("ClientID") || result.GetString("ClientID") != "SSH-2.0-Go-nray" {
		t.Fail()
	}
	if !result.IsSet("KexAlgorithms") || result.GetString("KexAlgorithms") != "" {
		t.Fail()
	}
	if !result.IsSet("HostKeyAlgorithms") || result.GetString("HostKeyAlgorithms") != "" {
		t.Fail()
	}
	if !result.IsSet("Ciphers") || result.GetString("Ciphers") != "" {
		t.Fail()
	}
	if !result.IsSet("CollectUserAuth") || result.GetBool("CollectUserAuth") != true {
		t.Fail()
	}
	if !result.IsSet("GexMinBits") || result.GetUint("GexMinBits") != 1024 {
		t.Fail()
	}
	if !result.IsSet("GexMaxBits") || result.GetUint("GexMaxBits") != 8192 {
		t.Fail()
	}
	if !result.IsSet("GexPreferredBits") || result.GetUint("GexPreferredBits") != 2048 {
		t.Fail()
	}
	if !result.IsSet("Verbose") || result.GetBool("Verbose") != false {
		t.Fail()
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", 400*time.Millisecond)
	viperWithValue.Set("CollectUserAuth", false)
	viperWithValue.Set("Verbose", true)

	result = utils.ApplyDefaultScannerZgrab2SSHConfig(viperWithValue)
	if !result.IsSet("subscribePorts") {
		t.Fail()
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 400*time.Millisecond {
		t.Fail()
	}
	if !result.IsSet("ClientID") || result.GetString("ClientID") != "SSH-2.0-Go-nray" {
		t.Fail()
	}
	if !result.IsSet("KexAlgorithms") || result.GetString("KexAlgorithms") != "" {
		t.Fail()
	}
	if !result.IsSet("HostKeyAlgorithms") || result.GetString("HostKeyAlgorithms") != "" {
		t.Fail()
	}
	if !result.IsSet("Ciphers") || result.GetString("Ciphers") != "" {
		t.Fail()
	}
	if !result.IsSet("CollectUserAuth") || result.GetBool("CollectUserAuth") != false {
		t.Fail()
	}
	if !result.IsSet("GexMinBits") || result.GetUint("GexMinBits") != 1024 {
		t.Fail()
	}
	if !result.IsSet("GexMaxBits") || result.GetUint("GexMaxBits") != 8192 {
		t.Fail()
	}
	if !result.IsSet("GexPreferredBits") || result.GetUint("GexPreferredBits") != 2048 {
		t.Fail()
	}
	if !result.IsSet("Verbose") || result.GetBool("Verbose") != true {
		t.Fail()
	}
}

func TestApplyDefaultScannerZgrab2HTTPConfig(t *testing.T) {
	var result *viper.Viper

	// Test passing nil to the function
	result = utils.ApplyDefaultScannerZgrab2HTTPConfig(nil)
	if !result.IsSet("subscribeHTTPPorts") {
		t.Fail()
	}
	if !result.IsSet("subscribeHTTPSPorts") {
		t.Fail()
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Fail()
	}
	if !result.IsSet("method") || result.GetString("method") != "GET" {
		t.Fail()
	}
	if !result.IsSet("endpoint") || result.GetString("endpoint") != "/" {
		t.Fail()
	}
	if !result.IsSet("userAgent") || result.GetString("userAgent") != "nray" {
		t.Fail()
	}
	if !result.IsSet("retryHTTPS") || result.GetBool("retryHTTPS") != false {
		t.Fail()
	}
	if !result.IsSet("maxSize") || result.GetUint("maxSize") != 256 {
		t.Fail()
	}
	if !result.IsSet("maxRedirects") || result.GetUint("maxRedirects") != 2 {
		t.Fail()
	}
	if !result.IsSet("heartbleed") || result.GetBool("heartbleed") != true {
		t.Fail()
	}
	if !result.IsSet("sessionTicket") || result.GetBool("sessionTicket") != true {
		t.Fail()
	}
	if !result.IsSet("extendedMasterSecret") || result.GetBool("extendedMasterSecret") != true {
		t.Fail()
	}
	if !result.IsSet("extendedRandom") || result.GetBool("extendedRandom") != true {
		t.Fail()
	}
	if !result.IsSet("noSNI") || result.GetBool("noSNI") != false {
		t.Fail()
	}
	if !result.IsSet("sctExt") || result.GetBool("sctExt") != false {
		t.Fail()
	}
	if !result.IsSet("keepClientLogs") || result.GetBool("keepClientLogs") != false {
		t.Fail()
	}
	if !result.IsSet("verifyServerCertificate") || result.GetBool("verifyServerCertificate") != false {
		t.Fail()
	}
	if !result.IsSet("minVersion") || result.GetUint("minVersion") != 0 {
		t.Fail()
	}
	if !result.IsSet("maxVersion") || result.GetUint("maxVersion") != 0 {
		t.Fail()
	}
	if !result.IsSet("noECDHE") || result.GetBool("noECDHE") != false {
		t.Fail()
	}
	if !result.IsSet("heartbeatEnabled") || result.GetBool("heartbeatEnabled") != true {
		t.Fail()
	}
	if !result.IsSet("dsaEnabled") || result.GetBool("dsaEnabled") != true {
		t.Fail()
	}

	// Test passing an empty viper to the function
	emptyViper := viper.New()
	result = utils.ApplyDefaultScannerZgrab2HTTPConfig(emptyViper)
	if !result.IsSet("subscribeHTTPPorts") {
		t.Fail()
	}
	if !result.IsSet("subscribeHTTPSPorts") {
		t.Fail()
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 2500*time.Millisecond {
		t.Fail()
	}
	if !result.IsSet("method") || result.GetString("method") != "GET" {
		t.Fail()
	}
	if !result.IsSet("endpoint") || result.GetString("endpoint") != "/" {
		t.Fail()
	}
	if !result.IsSet("userAgent") || result.GetString("userAgent") != "nray" {
		t.Fail()
	}
	if !result.IsSet("retryHTTPS") || result.GetBool("retryHTTPS") != false {
		t.Fail()
	}
	if !result.IsSet("maxSize") || result.GetUint("maxSize") != 256 {
		t.Fail()
	}
	if !result.IsSet("maxRedirects") || result.GetUint("maxRedirects") != 2 {
		t.Fail()
	}
	if !result.IsSet("heartbleed") || result.GetBool("heartbleed") != true {
		t.Fail()
	}
	if !result.IsSet("sessionTicket") || result.GetBool("sessionTicket") != true {
		t.Fail()
	}
	if !result.IsSet("extendedMasterSecret") || result.GetBool("extendedMasterSecret") != true {
		t.Fail()
	}
	if !result.IsSet("extendedRandom") || result.GetBool("extendedRandom") != true {
		t.Fail()
	}
	if !result.IsSet("noSNI") || result.GetBool("noSNI") != false {
		t.Fail()
	}
	if !result.IsSet("sctExt") || result.GetBool("sctExt") != false {
		t.Fail()
	}
	if !result.IsSet("keepClientLogs") || result.GetBool("keepClientLogs") != false {
		t.Fail()
	}
	if !result.IsSet("verifyServerCertificate") || result.GetBool("verifyServerCertificate") != false {
		t.Fail()
	}
	if !result.IsSet("minVersion") || result.GetUint("minVersion") != 0 {
		t.Fail()
	}
	if !result.IsSet("maxVersion") || result.GetUint("maxVersion") != 0 {
		t.Fail()
	}
	if !result.IsSet("noECDHE") || result.GetBool("noECDHE") != false {
		t.Fail()
	}
	if !result.IsSet("heartbeatEnabled") || result.GetBool("heartbeatEnabled") != true {
		t.Fail()
	}
	if !result.IsSet("dsaEnabled") || result.GetBool("dsaEnabled") != true {
		t.Fail()
	}

	// Pass a viper with a value explicitly set. The value mustn't change.
	viperWithValue := viper.New()
	viperWithValue.Set("timeout", 1000*time.Millisecond)
	viperWithValue.Set("endpoint", "/index.php")
	viperWithValue.Set("retryHTTPS", true)
	viperWithValue.Set("heartbleed", false)
	result = utils.ApplyDefaultScannerZgrab2HTTPConfig(viperWithValue)
	if !result.IsSet("subscribeHTTPPorts") {
		t.Fail()
	}
	if !result.IsSet("subscribeHTTPSPorts") {
		t.Fail()
	}
	if !result.IsSet("timeout") || result.GetDuration("timeout") != 1000*time.Millisecond {
		t.Fail()
	}
	if !result.IsSet("method") || result.GetString("method") != "GET" {
		t.Fail()
	}
	if !result.IsSet("endpoint") || result.GetString("endpoint") != "/index.php" {
		t.Fail()
	}
	if !result.IsSet("userAgent") || result.GetString("userAgent") != "nray" {
		t.Fail()
	}
	if !result.IsSet("retryHTTPS") || result.GetBool("retryHTTPS") != true {
		t.Fail()
	}
	if !result.IsSet("maxSize") || result.GetUint("maxSize") != 256 {
		t.Fail()
	}
	if !result.IsSet("maxRedirects") || result.GetUint("maxRedirects") != 2 {
		t.Fail()
	}
	if !result.IsSet("heartbleed") || result.GetBool("heartbleed") != false {
		t.Fail()
	}
	if !result.IsSet("sessionTicket") || result.GetBool("sessionTicket") != true {
		t.Fail()
	}
	if !result.IsSet("extendedMasterSecret") || result.GetBool("extendedMasterSecret") != true {
		t.Fail()
	}
	if !result.IsSet("extendedRandom") || result.GetBool("extendedRandom") != true {
		t.Fail()
	}
	if !result.IsSet("noSNI") || result.GetBool("noSNI") != false {
		t.Fail()
	}
	if !result.IsSet("sctExt") || result.GetBool("sctExt") != false {
		t.Fail()
	}
	if !result.IsSet("keepClientLogs") || result.GetBool("keepClientLogs") != false {
		t.Fail()
	}
	if !result.IsSet("verifyServerCertificate") || result.GetBool("verifyServerCertificate") != false {
		t.Fail()
	}
	if !result.IsSet("minVersion") || result.GetUint("minVersion") != 0 {
		t.Fail()
	}
	if !result.IsSet("maxVersion") || result.GetUint("maxVersion") != 0 {
		t.Fail()
	}
	if !result.IsSet("noECDHE") || result.GetBool("noECDHE") != false {
		t.Fail()
	}
	if !result.IsSet("heartbeatEnabled") || result.GetBool("heartbeatEnabled") != true {
		t.Fail()
	}
	if !result.IsSet("dsaEnabled") || result.GetBool("dsaEnabled") != true {
		t.Fail()
	}
}
