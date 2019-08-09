package targetgeneration

import (
	"regexp"

	"github.com/nray-scanner/nray/utils"

	"github.com/jmoiron/jsonq"

	"github.com/CaliDog/certstream-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type certificateTransparencyBackend struct {
	rawConfig    *viper.Viper
	domainRegex  *regexp.Regexp
	tcpPorts     []uint16
	udpPorts     []uint16
	maxHosts     uint
	maxTCPPorts  uint
	maxUDPPorts  uint
	hostnameChan chan string
	targetChan   chan AnyTargets
}

func (ct *certificateTransparencyBackend) configure(conf *viper.Viper) error {
	ct.rawConfig = conf
	log.WithFields(log.Fields{
		"module": "targetgeneration.certTransparencyBackend",
		"src":    "configure",
	}).Debug(conf.GetString("domainRegex"))
	ct.domainRegex = regexp.MustCompile(conf.GetString("domainRegex"))
	ct.maxHosts = uint(conf.GetInt("maxHostsPerBatch"))
	ct.maxTCPPorts = uint(conf.GetInt("maxTcpPortsPerBatch"))
	ct.maxUDPPorts = uint(conf.GetInt("maxUdpPortsPerBatch"))
	ct.tcpPorts = ParsePorts(conf.GetStringSlice("tcpports"), "tcp")
	ct.udpPorts = ParsePorts(conf.GetStringSlice("udpports"), "udp")
	ct.hostnameChan = make(chan string, 50)
	ct.targetChan = make(chan AnyTargets, 50)

	certstream, errStream := certstream.CertStreamEventStream(false)

	// Consume error stream
	go func(errStream chan error) {
		for err := range errStream {
			log.WithFields(log.Fields{
				"module": "targetgeneration.certTransparencyBackend",
				"src":    "configure",
			}).Warning(err.Error())
		}
	}(errStream)

	// Consume cert stream, get all domains and only use matching ones
	go func(certstream chan jsonq.JsonQuery) {
		for elem := range certstream {
			domains, err := elem.Array("data", "leaf_cert", "all_domains")
			utils.CheckError(err, false)
			for _, hostnameInterf := range domains {
				hostname := hostnameInterf.(string)
				if ct.domainRegex.MatchString(hostname) {
					ct.hostnameChan <- hostname
				}
			}
		}
	}(certstream)

	// Create any targets with correct chunking
	go ct.createTargets()

	return nil
}

func (ct *certificateTransparencyBackend) receiveTargets() <-chan AnyTargets {
	return ct.targetChan
}

func (ct *certificateTransparencyBackend) createTargets() {
	for {
		// Get the hosts for the next target batch
		hosts := make([]string, 0)
		for i := uint(0); i < ct.maxHosts; i++ {
			nextHost := <-ct.hostnameChan
			hosts = append(hosts, nextHost)
		}

		// Create the targets with chunked port lists
		targets := chunkPorts(hosts, ct.tcpPorts, ct.udpPorts, ct.maxTCPPorts, ct.maxUDPPorts)
		for _, target := range targets {
			ct.targetChan <- target
		}
	}
}
