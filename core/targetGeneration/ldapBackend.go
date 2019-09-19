package targetgeneration

import (
	"crypto/tls"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/ldap.v3"
)

type ldapBackend struct {
	rawConfig    *viper.Viper
	ldapQuery    string
	baseDn       string
	attribute    string
	ldapServer   string
	ldapPort     uint16
	insecure     bool
	ldapUser     string
	ldapPass     string
	tcpPorts     []uint16
	udpPorts     []uint16
	maxHosts     uint
	maxTCPPorts  uint
	maxUDPPorts  uint
	hostnameChan chan string
	targetChan   chan AnyTargets
}

func (ldapBack *ldapBackend) configure(conf *viper.Viper) error {
	conf = utils.ApplyDefaultTargetgeneratorLDAPConfig(conf)
	ldapBack.rawConfig = conf
	log.WithFields(log.Fields{
		"module": "targetgeneration.ldapBackend",
		"src":    "configure",
	}).Debug(conf.GetString("ldapSearchString"))
	ldapBack.ldapQuery = conf.GetString("ldapSearchString")
	ldapBack.baseDn = conf.GetString("baseDN")
	ldapBack.attribute = conf.GetString("ldapAttribute")
	ldapBack.ldapServer = conf.GetString("ldapServer")
	ldapBack.ldapPort = uint16(conf.GetInt("ldapPort"))
	ldapBack.insecure = conf.GetBool("insecure")
	ldapBack.ldapUser = conf.GetString("ldapUser")
	ldapBack.ldapPass = conf.GetString("ldapPass")
	ldapBack.maxHosts = uint(conf.GetInt("maxHostsPerBatch"))
	ldapBack.maxTCPPorts = uint(conf.GetInt("maxTcpPortsPerBatch"))
	ldapBack.maxUDPPorts = uint(conf.GetInt("maxUdpPortsPerBatch"))
	ldapBack.tcpPorts = ParsePorts(conf.GetStringSlice("tcpports"), "tcp")
	ldapBack.udpPorts = ParsePorts(conf.GetStringSlice("udpports"), "udp")
	ldapBack.hostnameChan = make(chan string, 50)
	ldapBack.targetChan = make(chan AnyTargets, 50)

	// Create any targets with correct chunking
	go ldapBack.createTargets()
	return nil
}

func (ldapBack *ldapBackend) receiveTargets() <-chan AnyTargets {
	return ldapBack.targetChan
}

func (ldapBack *ldapBackend) createTargets() {
	var l *ldap.Conn
	var err error
	if ldapBack.insecure {
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapBack.ldapServer, ldapBack.ldapPort))
		utils.CheckError(err, false)
		defer l.Close()
	} else {
		l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapBack.ldapServer, ldapBack.ldapPort), &tls.Config{InsecureSkipVerify: true})
		utils.CheckError(err, false)
	}

	// First bind with a read only user
	err = l.Bind(ldapBack.ldapUser, ldapBack.ldapPass)
	if err != nil {
		log.Fatal(err)
	}
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		ldapBack.baseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapBack.ldapQuery,
		[]string{ldapBack.attribute},
		nil,
	)
	sr, err := l.SearchWithPaging(searchRequest, uint32(ldapBack.maxHosts))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for _, entry := range sr.Entries {
			log.Debug(entry.GetAttributeValue(ldapBack.attribute))
			ldapBack.hostnameChan <- entry.GetAttributeValue(ldapBack.attribute)
		}
	}()

	for {
		// Get the hosts for the next target batch
		hosts := make([]string, 0)
		for i := uint(0); i < ldapBack.maxHosts; i++ {
			nextHost := <-ldapBack.hostnameChan
			hosts = append(hosts, nextHost)
		}
		// Create the targets with chunked port lists
		targets := chunkPorts(hosts, ldapBack.tcpPorts, ldapBack.udpPorts, ldapBack.maxTCPPorts, ldapBack.maxUDPPorts)
		for _, target := range targets {
			spew.Dump(target)
			ldapBack.targetChan <- target

		}
	}
}
