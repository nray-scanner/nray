package scanner

import (
	"encoding/json"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nray-scanner/nray/utils"
	"github.com/golang/protobuf/ptypes"

	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/spf13/viper"
	"github.com/zmap/zgrab2/lib/ssh"
	"github.com/zmap/zgrab2/modules"
)

// SSHScanner type encapsulates configuration for scanning SSH
// It implements the ProtocolScanner interface
type SSHScanner struct {
	nodeID          string
	nodeName        string
	timeout         time.Duration
	flags           modules.SSHFlags
	subscribedPorts []string
}

func initSSHFlags(configuration *viper.Viper) modules.SSHFlags {
	var confKexAlgos, confHostKeyAlgos, confCiphers string
	dummyConf := ssh.MakeSSHConfig()
	defaultHostKeyAlgos := strings.Join(dummyConf.HostKeyAlgorithms, ",")
	defaultKexAlgos := strings.Join(dummyConf.KeyExchanges, ",")
	defaultCiphers := strings.Join(dummyConf.Ciphers, ",")

	if confKexAlgos = configuration.GetString("KexAlgorithms"); confKexAlgos == "" {
		confKexAlgos = defaultKexAlgos
	}
	if confHostKeyAlgos = configuration.GetString("HostKeyAlgorithms"); confHostKeyAlgos == "" {
		confHostKeyAlgos = defaultHostKeyAlgos
	}
	if confCiphers = configuration.GetString("Ciphers"); confCiphers == "" {
		confCiphers = defaultCiphers
	}
	return modules.SSHFlags{
		ClientID:          configuration.GetString("ClientID"),
		KexAlgorithms:     confKexAlgos,
		HostKeyAlgorithms: confHostKeyAlgos,
		Ciphers:           confCiphers,
		CollectUserAuth:   configuration.GetBool("CollectUserAuth"),
		GexMinBits:        uint(configuration.GetInt("GexMinBits")),
		GexMaxBits:        uint(configuration.GetInt("GexMaxBits")),
		GexPreferredBits:  uint(configuration.GetInt("GexPreferredBits")),
		Verbose:           configuration.GetBool("Verbose"),
	}
}

// Configure is called with a configuration
func (sshscanner *SSHScanner) Configure(configuration *viper.Viper, nodeID string, nodeName string) {
	sshscanner.nodeID = nodeID
	sshscanner.nodeName = nodeName
	sshscanner.timeout = configuration.GetDuration("timeout")
	sshscanner.flags = initSSHFlags(configuration)
	sshscanner.subscribedPorts = configuration.GetStringSlice("subscribePorts")
}

// Register this scanner at the scan controller
func (sshscanner *SSHScanner) Register(scanctrl *ScanController) {
	for _, portSubscription := range sshscanner.subscribedPorts {
		scanctrl.Subscribe(portSubscription, sshscanner.getScanFunc())
	}
}

func (sshscanner *SSHScanner) getScanFunc() func(string, string, uint, chan<- *nraySchema.Event) func() {
	return func(protoParam string, hostParam string, portParam uint, resultChanParam chan<- *nraySchema.Event) func() {
		closuredPort := strconv.FormatUint(uint64(portParam), 10)
		closuredRhost := net.JoinHostPort(hostParam, closuredPort)
		closuredTimeout := sshscanner.timeout
		closuredClientID := sshscanner.flags.ClientID
		closuredHostKeyAlgos := sshscanner.flags.HostKeyAlgorithms
		closuredKexAlgorithms := sshscanner.flags.KexAlgorithms
		closuredCiphers := sshscanner.flags.Ciphers
		closuredVerbose := sshscanner.flags.Verbose
		closuredDontAuth := sshscanner.flags.CollectUserAuth
		closuredGexMinBits := sshscanner.flags.GexMinBits
		closuredGexMaxBits := sshscanner.flags.GexMaxBits
		closuredGexPreferredBits := sshscanner.flags.GexPreferredBits
		data := new(ssh.HandshakeLog)
		sshConfig := ssh.MakeSSHConfig()
		sshConfig.Timeout = closuredTimeout
		sshConfig.ConnLog = data
		sshConfig.ClientVersion = closuredClientID
		if err := sshConfig.SetHostKeyAlgorithms(closuredHostKeyAlgos); err != nil {
			log.Fatal(err)
		}
		if err := sshConfig.SetKexAlgorithms(closuredKexAlgorithms); err != nil {
			log.Fatal(err)
		}
		if err := sshConfig.SetCiphers(closuredCiphers); err != nil {
			log.Fatal(err)
		}
		sshConfig.Verbose = closuredVerbose
		sshConfig.DontAuthenticate = closuredDontAuth
		sshConfig.GexMinBits = closuredGexMinBits
		sshConfig.GexMaxBits = closuredGexMaxBits
		sshConfig.GexPreferredBits = closuredGexPreferredBits
		sshConfig.BannerCallback = func(banner string) error {
			data.Banner = strings.TrimSpace(banner)
			return nil
		}
		resultChan := resultChanParam
		return func() {
			timestamp, _ := ptypes.TimestampProto(currentTime())
			_, err := ssh.Dial("tcp", closuredRhost, sshConfig)
			utils.CheckError(err, false)
			jsonResult, err := json.Marshal(data)
			utils.CheckError(err, false)
			protoResult, err := utils.JSONtoProtoValue(jsonResult)
			utils.CheckError(err, false)

			resultChan <- &nraySchema.Event{
				NodeID:      sshscanner.nodeID,
				NodeName:    sshscanner.nodeName,
				Scannername: "zgrab2-ssh",
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
