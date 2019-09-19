package targetgeneration

import (
	"net"
	"strings"

	"github.com/spf13/viper"

	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
)

// standardTargetGenerator is the default target generator.
// It generates single domain targets as well as IP targets
// derived from networks using the ZMap algorithm
type standardTGBackend struct {
	rawConfig   *viper.Viper
	rawTargets  []string
	tcpPorts    []uint16
	udpPorts    []uint16
	maxHosts    uint
	maxTCPPorts uint
	maxUDPPorts uint
	blacklist   *NrayBlacklist
}

// Configure is called to set up the generator
func (generator *standardTGBackend) configure(conf *viper.Viper) error {
	conf = utils.ApplyDefaultTargetgeneratorStandardConfig(conf)
	generator.rawConfig = conf
	generator.rawTargets = conf.GetStringSlice("targets")
	generator.maxHosts = uint(conf.GetInt("maxHostsPerBatch"))
	generator.maxTCPPorts = uint(conf.GetInt("maxTcpPortsPerBatch"))
	generator.maxUDPPorts = uint(conf.GetInt("maxUdpPortsPerBatch"))

	if conf.IsSet("targetFile") && strings.Trim(conf.GetString("targetFile"), " ") != "" {
		targetHosts, err := utils.ReadFileLinesToStringSlice(conf.GetString("targetFile"))
		utils.CheckError(err, false)
		for _, target := range targetHosts {
			generator.rawTargets = append(generator.rawTargets, target)
		}
	}

	generator.blacklist = NewBlacklist()
	for _, blacklistItem := range conf.GetStringSlice("blacklist") {
		_ = generator.blacklist.AddToBlacklist(blacklistItem)
	}
	if conf.IsSet("blacklistFile") && strings.Trim(conf.GetString("blacklistFile"), " ") != "" {
		blacklistHosts, err := utils.ReadFileLinesToStringSlice(conf.GetString("blacklistFile"))
		utils.CheckError(err, false)
		for _, blacklistItem := range blacklistHosts {
			_ = generator.blacklist.AddToBlacklist(blacklistItem)
		}
	}

	generator.tcpPorts = ParsePorts(conf.GetStringSlice("tcpports"), "tcp")
	generator.udpPorts = ParsePorts(conf.GetStringSlice("udpports"), "udp")

	return nil
}

// ReceiveTargets implements the interface stub and returns a channel with targets
// All targets have been generated when the channel is closed
func (generator *standardTGBackend) receiveTargets() <-chan AnyTargets {
	resultChan := make(chan AnyTargets, 10) // Keeping 10 Targets waiting should be sufficient

	// All targets are sent over this channel
	targets := make(chan string, 50)
	// Decides if input is an IP, net or domain and fills the target channel with target strings
	go func(targetChan chan<- string, rawTargets []string) {
		for _, rawTarget := range rawTargets {
			if ipv4NetRegexpr.MatchString(rawTarget) { // An IPv4 network
				_, ipnet, err := net.ParseCIDR(rawTarget)
				utils.CheckError(err, true)
				ipStream := GenerateIPStreamFromCIDR(ipnet, generator.blacklist)
				for ip := range ipStream {
					targets <- ip.String()
				}
			} else if ipv4Regexpr.MatchString(rawTarget) { // An IPv4 address
				if !generator.blacklist.IsIPBlacklisted(rawTarget) {
					targets <- rawTarget
				}
			} else if mayBeFQDN(rawTarget) { // Probably a FQDN
				if !generator.blacklist.IsDNSNameBlacklisted(rawTarget) {
					targets <- rawTarget
				}
			} else {
				log.WithFields(log.Fields{
					"module": "targetgeneration.standardTGBackend",
					"src":    "receiveTargets",
				}).Debugf("This does not look like a valid target: %s", rawTarget)
			}
		}
		close(targets)
	}(targets, generator.rawTargets)

	// The idea is as follows:
	// 0. Do as long as the internal generator is creating targets:
	//   1. Get maxHosts many next targets from the internal generator
	//   2. Get a stream for TCP and UDP ports
	//   3. As long as both streams are not closed, do:
	//     4. Create new AnyTarget with hosts generated earlier included
	//     5. use the streams to fill TCP and UDP ports of AnyTarget object up to
	//     maxTcp/maxUdpPorts or streams are closed (done in chunkPorts())
	//     6. send the AnyTarget back
	// 7. When the host generator is done, close the stream
	go func(resultChan chan<- AnyTargets, targets <-chan string) {
		var stop bool
		for !stop {
			// Get the hosts
			hosts := make([]string, 0)

			for i := uint(0); i < generator.maxHosts; i++ {
				elem, ok := <-targets
				if !ok { // We're done, set stop mark, process remaining hosts and stop
					stop = true
					break
				}
				hosts = append(hosts, elem)
			}
			for _, target := range chunkPorts(hosts, generator.tcpPorts, generator.udpPorts, generator.maxTCPPorts, generator.maxUDPPorts) {
				resultChan <- target
			}
		}
		close(resultChan)
	}(resultChan, targets)

	return resultChan
}
