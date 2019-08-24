package scanner

import (
	"encoding/json"
	"time"

	"github.com/golang/protobuf/ptypes"
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/viper"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/http"
)

// HTTPScanner type encapsulates configuration for scanning HTTP
// It implements the ProtocolScanner interface
type HTTPScanner struct {
	nodeID               string
	nodeName             string
	timeout              time.Duration
	subscribedHTTPPorts  []string
	subscribedHTTPSPorts []string
	viperConfig          *viper.Viper
}

// initialises HTTP flags with configuration and sets defaults
// NOTE: Port and other runtime config (HTTP vs. HTTPS?) is encoded
// in this struct, therefore this generates rather a template
// that is to be modified again for each scan.
func initHTTPFlags(configuration *viper.Viper) http.Flags {
	utils.CreateDefaultScannerZgrab2HTTPConfig(configuration)
	// Define defaults
	confTimeout := 2500 * time.Millisecond
	confTLSHeartbleed := true
	confTLSSessionTicket := true
	confTLSExtendedMasterSecret := true
	confTLSExtendedRandom := true
	confTLSNoSNI := false
	confTLSSctExt := false
	confTLSKeepClientLogs := false
	confTLSVerifyServerCertificate := false
	confTLSMinVersion := 0
	confTLSMaxVersion := 0
	confTLSNoECDHE := false
	confTLSHeartbeatEnabled := true
	confTLSDsaEnabled := true
	confMethod := "GET"
	confEndpoint := "/"
	confUserAgent := "nray port scanner"
	confRetryHTTPS := true // Changed later depending on HTTP/HTTPS scan
	confMaxSize := 256
	confMaxRedirects := 5

	if configuration.IsSet("timeout") {
		confTimeout = configuration.GetDuration("timeout")
	}
	if configuration.IsSet("tls.heartbleed") {
		confTLSHeartbleed = configuration.GetBool("tls.heartbleed")
	}
	if configuration.IsSet("tls.sessionTicket") {
		confTLSSessionTicket = configuration.GetBool("tls.sessionTicket")
	}
	if configuration.IsSet("tls.extendedMasterSecret") {
		confTLSExtendedMasterSecret = configuration.GetBool("tls.extendedMasterSecret")
	}
	if configuration.IsSet("tls.extendedRandom") {
		confTLSExtendedRandom = configuration.GetBool("tls.extendedRandom")
	}
	if configuration.IsSet("tls.noSNI") {
		confTLSNoSNI = configuration.GetBool("tls.noSNI")
	}
	if configuration.IsSet("tls.sctExt") {
		confTLSSctExt = configuration.GetBool("tls.sctExt")
	}
	if configuration.IsSet("tls.keepClientLogs") {
		confTLSKeepClientLogs = configuration.GetBool("tls.keepClientLogs")
	}
	if configuration.IsSet("verifyServerCertificate") {
		confTLSVerifyServerCertificate = configuration.GetBool("tls.verifyServerCertificate")
	}
	if configuration.IsSet("tls.minVersion") {
		confTLSMinVersion = configuration.GetInt("tls.minVersion")
	}
	if configuration.IsSet("tls.maxVersion") {
		confTLSMaxVersion = configuration.GetInt("tls.maxVersion")
	}
	if configuration.IsSet("tls.noECDHE") {
		confTLSNoECDHE = configuration.GetBool("tls.noECDHE")
	}
	if configuration.IsSet("tls.heartbeatEnabled") {
		confTLSHeartbeatEnabled = configuration.GetBool("tls.heartbeatEnabled")
	}
	if configuration.IsSet("tls.dsaEnabled") {
		confTLSDsaEnabled = configuration.GetBool("tls.dsaEnabled")
	}
	if configuration.IsSet("method") {
		confMethod = configuration.GetString("method")
	}
	if configuration.IsSet("endpoint") {
		confEndpoint = configuration.GetString("endpoint")
	}
	if configuration.IsSet("userAgent") {
		confUserAgent = configuration.GetString("userAgent")
	}
	if configuration.IsSet("retryHTTPS") {
		confRetryHTTPS = configuration.GetBool("retryHTTPS")
	}
	if configuration.IsSet("maxSize") {
		confMaxSize = configuration.GetInt("maxSize")
	}
	if configuration.IsSet("maxRedirects") {
		confMaxRedirects = configuration.GetInt("maxRedirects")
	}
	// TODO: Make other stuff (like ciphersuites) also configurable
	flags := http.Flags{
		BaseFlags: zgrab2.BaseFlags{
			Port:    0,
			Timeout: confTimeout,
		},
		// Taken from ZGrab2 source. I tried to take reasonable defaults but I'm not a TLS expert, especially when it comes to opinionated parts
		TLSFlags: zgrab2.TLSFlags{
			Heartbleed:           confTLSHeartbleed,           // bool `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed"`
			SessionTicket:        confTLSSessionTicket,        //        bool `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
			ExtendedMasterSecret: confTLSExtendedMasterSecret, // bool `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
			ExtendedRandom:       confTLSExtendedRandom,       //      bool `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
			NoSNI:                confTLSNoSNI,                //                bool `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
			SCTExt:               confTLSSctExt,               //               bool `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`
			KeepClientLogs:       confTLSKeepClientLogs,       // bool `long:"keep-client-logs" description:"Include the client-side logs in the TLS handshake"`

			//Time string `long:"time" description:"Explicit request time to use, instead of clock. YYYYMMDDhhmmss format."`
			// TODO: directory? glob? How to map server name -> certificate?
			//Certificates string `long:"certificates" description:"Set of certificates to present to the server"`
			// TODO: re-evaluate this, or at least specify the file format
			//CertificateMap string `long:"certificate-map" description:"A file mapping server names to certificates"`
			// TODO: directory? glob?
			//RootCAs string `long:"root-cas" description:"Set of certificates to use when verifying server certificates"`
			// TODO: format?
			//NextProtos              string `long:"next-protos" description:"A list of supported application-level protocols"`
			//ServerName              string `long:"server-name" description:"Server name used for certificate verification and (optionally) SNI"`
			VerifyServerCertificate: confTLSVerifyServerCertificate, // bool   `long:"verify-server-certificate" description:"If set, the scan will fail if the server certificate does not match the server-name, or does not chain to a trusted root."`
			// TODO: format? mapping? zgrab1 had flags like ChromeOnly, FirefoxOnly, etc...
			//CipherSuite      string `long:"cipher-suite" description:"A comma-delimited list of hex cipher suites to advertise."`
			MinVersion: confTLSMinVersion, //       int    `long:"min-version" description:"The minimum SSL/TLS version that is acceptable. 0 means that SSLv3 is the minimum."`
			MaxVersion: confTLSMaxVersion, //      int    `long:"max-version" description:"The maximum SSL/TLS version that is acceptable. 0 means use the highest supported value."`
			//CurvePreferences string `long:"curve-preferences" description:"A list of elliptic curves used in an ECDHE handshake, in order of preference."`
			NoECDHE: confTLSNoECDHE, //          bool   `long:"no-ecdhe" description:"Do not allow ECDHE handshakes"`
			// TODO: format?
			//SignatureAlgorithms string `long:"signature-algorithms" description:"Signature and hash algorithms that are acceptable"`
			HeartbeatEnabled: confTLSHeartbeatEnabled, //    bool   `long:"heartbeat-enabled" description:"If set, include the heartbeat extension"`
			DSAEnabled:       confTLSDsaEnabled,       //          bool   `long:"dsa-enabled" description:"Accept server DSA keys"`
			// TODO: format?
			//ClientRandom string `long:"client-random" description:"Set an explicit Client Random (base64 encoded)"`
			// TODO: format?
			//ClientHello string `long:"client-hello" description:"Set an explicit ClientHello (base64 encoded)"`
		},
		Method:       confMethod,
		Endpoint:     confEndpoint,
		UserAgent:    confUserAgent,
		RetryHTTPS:   confRetryHTTPS,
		MaxSize:      confMaxSize,      // Max kilobytes to read in response to an HTTP request
		MaxRedirects: confMaxRedirects, // Redirects may cross port boundaries. If e.g. port 80 redirects you to port 5000, the scanner is going to follow this redirect
	}
	return flags
}

func (httpscanner *HTTPScanner) prepareFlags(useTLS bool) http.Flags {
	flags := initHTTPFlags(httpscanner.viperConfig)
	if useTLS {
		flags.UseHTTPS = true
		flags.RetryHTTPS = true
	} else {
		flags.UseHTTPS = false
	}
	return flags
}

// Configure is called with a configuration
func (httpscanner *HTTPScanner) Configure(configuration *viper.Viper, nodeID string, nodeName string) {
	httpscanner.nodeID = nodeID
	httpscanner.nodeName = nodeName
	httpscanner.viperConfig = configuration
	httpscanner.timeout = configuration.GetDuration("timeout")
	httpscanner.subscribedHTTPPorts = configuration.GetStringSlice("subscribeHTTPPorts")
	httpscanner.subscribedHTTPSPorts = configuration.GetStringSlice("subscribeHTTPSPorts")
}

// Register this scanner at the scan controller
func (httpscanner *HTTPScanner) Register(scanctrl *ScanController) {
	for _, portSubscription := range httpscanner.subscribedHTTPPorts {
		httpFlags := httpscanner.prepareFlags(false)
		scanctrl.Subscribe(portSubscription, httpscanner.getScanFunc(httpFlags))
	}
	for _, portSubscription := range httpscanner.subscribedHTTPSPorts {
		httpsFlags := httpscanner.prepareFlags(true)
		scanctrl.Subscribe(portSubscription, httpscanner.getScanFunc(httpsFlags))
	}
}

func (httpscanner *HTTPScanner) getScanFunc(httpflags http.Flags) func(string, string, uint, chan<- *nraySchema.Event) func() {
	return func(protoParam string, hostParam string, portParam uint, resultChanParam chan<- *nraySchema.Event) func() {
		closuredFlags := httpflags
		resultChan := resultChanParam
		closuredRhost := hostParam
		closuredPort := portParam
		return func() {
			var HTTPModule http.Module
			var flags = &closuredFlags
			flags.Port = closuredPort
			scanner := HTTPModule.NewScanner()
			scanner.Init(flags)

			target := zgrab2.ScanTarget{Domain: closuredRhost}
			timestamp, _ := ptypes.TimestampProto(currentTime())

			_, results, err := scanner.Scan(target)
			utils.CheckError(err, false)
			jsonResult, err := json.Marshal(results)
			utils.CheckError(err, false)
			protoResult, err := utils.JSONtoProtoValue(jsonResult)
			utils.CheckError(err, false)

			resultChan <- &nraySchema.Event{
				NodeID:      httpscanner.nodeID,
				NodeName:    httpscanner.nodeName,
				Scannername: "zgrab2-http",
				Timestamp:   timestamp,
				EventData: &nraySchema.Event_Result{
					Result: &nraySchema.ScanResult{
						Target: hostParam,
						Port:   uint32(portParam),
						Result: &nraySchema.ScanResult_Zgrabscan{
							Zgrabscan: &nraySchema.ZGrab2ScanResult{
								JsonResult: protoResult,
							},
						},
					},
				},
			}
		}
	}
}
