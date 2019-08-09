package scanner

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"encoding/hex"

	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// UDPScanner contains the configuration for this scanner
// TODO: allow own port/payload associations via config
type UDPScanner struct {
	fast           bool
	timeout        time.Duration
	payloads       *map[uint32][]byte
	defaultPayload []byte
}

func udpProtoScan(target string, port uint32, config UDPScanner) (*PortscanResult, error) {
	// Get proto payload
	payload, ok := (*config.payloads)[port]
	if !ok {
		if config.fast {
			return nil, fmt.Errorf("Fast UDP scanning enabled and no payload known for UDP port %d", port)
		}
		// Load default payload
		payload = config.defaultPayload
	}

	if target == "" {
		return nil, fmt.Errorf("target is nil")
	}
	// UDP is connectionless, so establishing the "connection" has the timeout applied for e.g. DNS resolution
	// In case of an IP address this should return immediately
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), config.timeout)
	if err != nil && strings.Contains(err.Error(), "socket: too many open files") {
		return nil, fmt.Errorf("Too many open files. You are running too many scan workers and the OS is limiting file descriptors. YOU ARE MISSING SCAN RESULTS. Scan with less workers")
	}
	utils.CheckError(err, false)
	defer conn.Close()
	// This is the real timeout that is applied. We send a packet and wait for a response or receive an error in case of timeout
	conn.SetDeadline(time.Now().Add(config.timeout))
	conn.Write(payload)
	if err != nil {
		log.WithFields(log.Fields{
			"module": "scanner.udp",
			"src":    "udpProtoScan",
		}).Warning(err.Error())

		utils.CheckError(err, false)
		return nil, nil
	}
	// If reading throws an error, the port is closed (indicated by ICMP Type 3 Code 3 sent by target or by a timeout)
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return nil, nil
	}
	result := PortscanResult{
		Target:   target,
		Port:     port,
		Open:     true,
		Scantype: "udp",
		Timeout:  config.timeout,
	}
	return &result, nil
}

// Configure sets relevant configuration on this scanner
func (udpscan *UDPScanner) Configure(config *viper.Viper) {
	udpscan.timeout = config.GetDuration("timeout")
	udpscan.fast = config.GetBool("fast")
	decoded := []byte(config.GetString("defaultHexPayload"))
	udpscan.defaultPayload = []byte(decoded)
	p := make(map[uint32][]byte)
	udpscan.payloads = &p
	(*udpscan.payloads)[1604] = probePktCitrix()
	(*udpscan.payloads)[53] = probePktDNS()
	(*udpscan.payloads)[137] = probePktNetBios()
	(*udpscan.payloads)[123] = probePktNTP()
	(*udpscan.payloads)[524] = probePktDB2DISCO()
	(*udpscan.payloads)[5093] = probePktSentinel()
	(*udpscan.payloads)[1434] = probePktMSSQL()
	(*udpscan.payloads)[161] = probePktSNMPv2()
	(*udpscan.payloads)[111] = probePktPortmap()

	customPayloads := config.GetStringMapString("customHexPayloads")
	for customPayloadPort, customPayload := range customPayloads {
		p, err := strconv.ParseUint(customPayloadPort, 10, 32)
		utils.CheckError(err, false)
		(*udpscan.payloads)[uint32(p)] = []byte(customPayload)
	}
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L476
func probePktCitrix() []byte {
	res, err := hex.DecodeString("1e00013002fda8e300000000000000000000000000000000000000000000")
	utils.CheckError(err, false)
	return res
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L374
func probePktDNS() []byte {
	// Not cryptographically relevant, so seeding with time should be OK
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// DNS session ID is randomized
	dnsSessionID := make([]byte, 2)
	r.Read(dnsSessionID)
	// Ask for resolution of "VERSION.BIND"
	body := []byte("\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
		"\x07" + "VERSION" +
		"\x04" + "BIND" +
		"\x00\x00\x10\x00\x03")
	return append(dnsSessionID, body...)
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L384
func probePktNetBios() []byte {
	// Not cryptographically relevant, so seeding with time should be OK
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	sessionID := make([]byte, 2)
	r.Read(sessionID)
	body := []byte("\x00\x00\x00\x01\x00\x00\x00\x00" +
		"\x00\x00\x20\x43\x4b\x41\x41\x41" +
		"\x41\x41\x41\x41\x41\x41\x41\x41" +
		"\x41\x41\x41\x41\x41\x41\x41\x41" +
		"\x41\x41\x41\x41\x41\x41\x41\x41" +
		"\x41\x41\x41\x00\x00\x21\x00\x01")
	return append(sessionID, body...)
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L417
func probePktNTP() []byte {
	return []byte("\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3")
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L471
func probePktDB2DISCO() []byte {
	return []byte("DB2GETADDR\x00SQL05000\x00")
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L427
func probePktSentinel() []byte {
	return []byte("\x7a\x00\x00\x00\x00\x00")
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L413
func probePktMSSQL() []byte {
	return []byte("\x02")
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L451
func probePktSNMPv2() []byte {
	// TODO: Go down the ASN.1 rabbit hole. Until then, the payload extracted from a network capture has to suffice
	return []byte("0)\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04w]l\xb1\x02\x01\x00\x02\x01\x000\x0e0\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00")
}

// https://github.com/rapid7/metasploit-framework/blob/eeed14d2a27759e369d48331b0959008a0b24df8/modules/auxiliary/scanner/discovery/udp_sweep.rb#L397
func probePktPortmap() []byte {
	// Not cryptographically relevant, so seeding with time should be OK
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	XID := make([]byte, 4)
	r.Read(XID)
	payload := []byte("\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	return append(XID, payload...)
}
