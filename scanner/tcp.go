package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// PortscanResult is the struct that contains all information about the scan and the results
type PortscanResult struct {
	Target   string        `json:"Target"`
	Port     uint32        `json:"Port"`
	Open     bool          `json:"Open"`
	Scantype string        `json:"Scantype"`
	Timeout  time.Duration `json:"Timeout"`
}

// TCPConnectIsOpen uses the operating system's mechanism to open a
// TCP connection to a given target IP address at a given port.
// Timeout specifies how long to wait before aborting the connection
// attempt
func TCPConnectIsOpen(target string, port uint32, timeout time.Duration) (*PortscanResult, error) {
	if target == "" {
		return nil, fmt.Errorf("target is nil")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			log.WithFields(log.Fields{
				"module": "scanner.tcp",
				"src":    "tcpConnectIsOpen",
			}).Warning("Too many open files. You are running too many scan workers and the OS is limiting file descriptors. YOU ARE MISSING SCAN RESULTS. Scan with less workers")
		}
		return nil, nil // port is closed
	}
	defer conn.Close()
	result := PortscanResult{
		Target:   target,
		Port:     port,
		Open:     true,
		Scantype: "tcpconnect",
		Timeout:  timeout,
	}
	return &result, nil
}

// TCPScanner represents the built-in TCP scanning functionality of nray
// If using other existing scanners or different scanning approaches are
// required, it should not be hard to replace this
type TCPScanner struct {
	timeout time.Duration
}

// Configure loads a viper configuration and sets the appropriate values
func (tcpscan *TCPScanner) Configure(config *viper.Viper) {
	config = utils.ApplyDefaultScannerTCPConfig(config)
	tcpscan.timeout = config.GetDuration("timeout")
}
