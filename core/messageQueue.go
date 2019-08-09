package core

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	mangos "nanomsg.org/go/mangos/v2"
	"nanomsg.org/go/mangos/v2/protocol/rep"
	"nanomsg.org/go/mangos/v2/protocol/req"
)

// Creates the server's rep socket
func createRepSock(host string, ports []uint32, tlsconfig *tls.Config) mangos.Socket {
	sock, err := rep.NewSocket()
	utils.CheckError(err, false)
	listenOptions := make(map[string]interface{})
	for _, port := range ports {
		var listenAddr string
		if tlsconfig != nil {
			listenOptions[mangos.OptionTLSConfig] = tlsconfig
			listenAddr = fmt.Sprintf("tls+tcp://%s:%d", host, port)

		} else {
			listenAddr = fmt.Sprintf("tcp://%s:%d", host, port)
		}
		log.WithFields(log.Fields{
			"module": "core.messageQueue",
			"src":    "createRepSock",
		}).Debugf("Trying to listen on: %s", listenAddr)
		sock.ListenOptions(listenAddr, listenOptions)
		utils.CheckError(err, true)
	}
	return sock
}

// Checks server and port and connects to the server
func initServerConnection(server, port string, socketconfig map[string]interface{}) mangos.Socket {
	if server == "" || port == "" {
		log.WithFields(log.Fields{
			"module": "core.messageQueue",
			"src":    "initServerConnection",
		}).Error("Please specify a server and the port of the upstream nray server")
		os.Exit(1)
	}
	sock, err := req.NewSocket()
	utils.CheckError(err, true)
	sock.SetOption(mangos.OptionRecvDeadline, recvDeadline)
	sock.SetOption(mangos.OptionSendDeadline, sendDeadline)
	var serverAddress string
	if socketconfig[mangos.OptionTLSConfig] != nil {
		serverAddress = fmt.Sprintf("tls+tcp://%s:%s", server, port)
	} else {
		serverAddress = fmt.Sprintf("tcp://%s:%s", server, port)
	}
	log.WithFields(log.Fields{
		"module": "core.messageQueue",
		"src":    "InitServerConnection",
	}).Infof("Connecting to: %s", serverAddress)
	err = sock.DialOptions(serverAddress, socketconfig)
	utils.CheckError(err, true)
	return sock
}

func setupMangosClientTLSConfig(useTLS bool, ignoreServerCertificate bool, serverCertPath string, clientCertPath string, clientKeyPath string, serverName string) (map[string]interface{}, error) {
	connectOptions := make(map[string]interface{})
	if !useTLS {
		return connectOptions, nil
	}
	var tlsConfig = &tls.Config{}
	tlsConfig.Rand = rand.Reader

	// Ignore server cert?
	if ignoreServerCertificate {
		log.WithFields(log.Fields{
			"module": "core.messageQueue",
			"src":    "setupMangosClientTLSConfig",
		}).Warning("Server certificate checks are disabled. Anybody may intercept and modify your traffic.")
		tlsConfig.InsecureSkipVerify = ignoreServerCertificate
	}

	// Pin server cert?
	if serverCertPath != "" {
		cert, err := ioutil.ReadFile(serverCertPath)
		utils.CheckError(err, true)
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(cert)
		if !ok {
			return nil, fmt.Errorf("Failed to parse server certificate from file %s", serverCertPath)
		}
		tlsConfig.RootCAs = roots
	}

	// Set server name
	// See https://stackoverflow.com/a/12122718 comments
	tlsConfig.ServerName = serverName

	// Client key for mutual auth?
	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		utils.CheckError(err, true)
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	tlsConfig.BuildNameToCertificate()
	connectOptions[mangos.OptionTLSConfig] = tlsConfig
	return connectOptions, nil
}
