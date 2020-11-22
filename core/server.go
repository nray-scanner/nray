package core

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/nray-scanner/nray/events"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"

	targetgeneration "github.com/nray-scanner/nray/core/targetGeneration"
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/viper"

	// TCP transport for nanomsg
	_ "nanomsg.org/go/mangos/v2/transport/tcp"
	_ "nanomsg.org/go/mangos/v2/transport/tlstcp"

	mangos "nanomsg.org/go/mangos/v2"
)

// CurrentConfig is the initialized struct containing
// the configuration
var CurrentConfig GlobalConfig
var externalConfig *viper.Viper

// InitGlobalServerConfig initializes the GlobalConfig
// from the values provided by viper
func InitGlobalServerConfig(config *viper.Viper) error {
	externalConfig = config
	if externalConfig.GetBool("debug") {
		log.SetLevel(log.DebugLevel)
		log.SetFormatter(&utils.Formatter{
			HideKeys: true,
		})
	}

	// Init ports
	portsToListen := externalConfig.GetStringSlice("listen")
	if len(portsToListen) == 0 || portsToListen == nil {
		return fmt.Errorf("No port to bind to was given")
	}
	portList := make([]uint32, 0)
	for _, port := range portsToListen {
		val, err := strconv.ParseUint(port, 10, 32)
		utils.CheckError(err, false)
		portList = append(portList, uint32(val))
	}

	// Init host configuration
	host := externalConfig.GetString("host")
	CurrentConfig = GlobalConfig{ListenPorts: portList, ListenHost: host}

	// Init TLS
	if externalConfig.GetBool("TLS.enabled") {
		cert, err := tls.LoadX509KeyPair(externalConfig.GetString("TLS.cert"), externalConfig.GetString("TLS.key"))
		utils.CheckError(err, true)
		CurrentConfig.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		CurrentConfig.TLSConfig.Rand = rand.Reader
		CurrentConfig.TLSConfig.BuildNameToCertificate()
		if externalConfig.GetBool("TLS.forceClientAuth") {
			caCert, err := ioutil.ReadFile(externalConfig.GetString("TLS.CA"))
			utils.CheckError(err, true)
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			CurrentConfig.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			CurrentConfig.TLSConfig.ClientCAs = caCertPool
		}
	}

	// Init pool configuration
	CurrentConfig.Pools = make([]*Pool, externalConfig.GetInt("pools"))

	// Init event handlers
	CurrentConfig.EventHandlers = make([]events.EventHandler, 0)
	for _, eventHandlerName := range events.RegisteredHandlers {
		configPath := fmt.Sprintf("events.%s", eventHandlerName)
		if externalConfig.IsSet(configPath) {
			handler := events.GetEventHandler(eventHandlerName)
			err := handler.Configure(externalConfig.Sub(configPath))
			utils.CheckError(err, true)
			CurrentConfig.EventHandlers = append(CurrentConfig.EventHandlers, handler)
		}
	}
	return nil
}

// Start starts the core
func Start() {
	server(CurrentConfig)
}

// Here does (most of) the core magic happen. It's long, but don't get afraid
func server(currentConfig GlobalConfig) {
	// Create node pools
	initPools()

	// Initialise Message Queue and bind to TCP ports
	sock := createRepSock(currentConfig.ListenHost, currentConfig.ListenPorts, currentConfig.TLSConfig)
	defer sock.Close()

	// Handle Ctrl+C events
	startSignalInterruptHandler()

	// Main Loop. Receives data from nodes, processes it and sends replies
mainloop:
	for {
		msg, err := sock.Recv()
		utils.CheckError(err, false)
		skeleton := &nraySchema.NrayNodeMessage{}
		err = proto.Unmarshal(msg, skeleton)
		utils.CheckError(err, false)

		// TODO: Move this into own function
		// Here are all incoming messages processed
		switch skeleton.MessageContent.(type) {
		case *nraySchema.NrayNodeMessage_NodeRegister:
			registeredNode := handleNodeRegister(skeleton.GetNodeRegister(), externalConfig.GetBool("considerClientPoolPreference"), externalConfig.GetBool("allowMultipleNodesPerHost"))
			for _, handler := range currentConfig.EventHandlers {
				handler.ProcessEvents([]*nraySchema.Event{skeleton.GetNodeRegister().Envinfo})
			}
			if externalConfig.IsSet("scannerconfig") {
				registeredNode.Scannerconfig, err = json.Marshal(externalConfig.Sub("scannerconfig").AllSettings())
			} else {
				registeredNode.Scannerconfig = nil
			}
			utils.CheckError(err, false)
			serverMessage := &nraySchema.NrayServerMessage{
				MessageContent: &nraySchema.NrayServerMessage_RegisteredNode{
					RegisteredNode: registeredNode,
				},
			}
			SendMessage(sock, serverMessage)
		case *nraySchema.NrayNodeMessage_Heartbeat:
			if alreadyRegistered := checkNodeIDIsRegistered(skeleton.GetHeartbeat().NodeID); !alreadyRegistered {
				SendMessage(sock, createUnregisteredMessage(skeleton.GetHeartbeat().NodeID))
			} else {
				heartBeatAck := handleHeartbeat(skeleton.GetHeartbeat())
				serverMessage := &nraySchema.NrayServerMessage{
					MessageContent: &nraySchema.NrayServerMessage_HeartbeatAck{
						HeartbeatAck: heartBeatAck,
					},
				}
				SendMessage(sock, serverMessage)
			}
		case *nraySchema.NrayNodeMessage_MoreWork:
			if alreadyRegistered := checkNodeIDIsRegistered(skeleton.GetMoreWork().NodeID); !alreadyRegistered {
				SendMessage(sock, createUnregisteredMessage(skeleton.GetMoreWork().NodeID))
			}
			nodeID := handleMoreWorkRequest(skeleton.GetMoreWork())
			var marshalled []byte
			for _, pool := range currentConfig.Pools {
				node, exists := pool.getNodeFromID(nodeID)
				if exists {
					log.WithFields(log.Fields{
						"module": "core.server",
						"src":    "server",
					}).Debugf("Request for more work by node %s", node.Name)

					newJob := pool.GetJobForNode(nodeID)
					if newJob == nil {
						// Currently no jobs available :(
						marshalled = createMoreWorkMsg(targetgeneration.AnyTargets{}, 0)
					} else {
						marshalled = createMoreWorkMsg(newJob.workItems, newJob.id)
					}
				}
			}
			err = sock.Send(marshalled)
			utils.CheckError(err, false)
		case *nraySchema.NrayNodeMessage_WorkDone:
			if alreadyRegistered := checkNodeIDIsRegistered(skeleton.GetWorkDone().NodeID); !alreadyRegistered {
				SendMessage(sock, createUnregisteredMessage(skeleton.GetWorkDone().NodeID))
			} else {
				currentConfig.LogEvents(skeleton.GetWorkDone().Events)
				nodeID := skeleton.GetWorkDone().NodeID
				poolOfNode := currentConfig.getPoolFromNodeID(nodeID)
				err := poolOfNode.removeJobFromJobArea(nodeID, skeleton.GetWorkDone().Batchid)
				utils.CheckError(err, false)
				serverMessage := &nraySchema.NrayServerMessage{
					MessageContent: &nraySchema.NrayServerMessage_WorkDoneAck{
						WorkDoneAck: &nraySchema.WorkDoneAck{},
					},
				}
				SendMessage(sock, serverMessage)
			}
		case *nraySchema.NrayNodeMessage_Goodbye:
			if alreadyRegistered := checkNodeIDIsRegistered(skeleton.GetGoodbye().NodeID); !alreadyRegistered {
				SendMessage(sock, createUnregisteredMessage(skeleton.GetGoodbye().NodeID))
			} else {
				nodeID := skeleton.GetGoodbye().NodeID
				for _, pool := range currentConfig.Pools {
					_, exists := pool.getNodeFromID(nodeID)
					var success bool
					if exists {
						success = pool.removeNodeFromPool(nodeID, false)
						serverMessage := &nraySchema.NrayServerMessage{
							MessageContent: &nraySchema.NrayServerMessage_GoodbyeAck{
								GoodbyeAck: &nraySchema.GoodbyeAck{
									Ok: success,
								},
							},
						}
						SendMessage(sock, serverMessage)
						break
					}
				}
			}
		case nil:
			log.WithFields(log.Fields{
				"module": "core.server",
				"src":    "server",
			}).Warning("Message sent by node is empty")
		default:
			log.WithFields(log.Fields{
				"module": "core.server",
				"src":    "server",
			}).Error("Cannot decode message sent by node")
		}

		// If the Job queue is empty and job generation is done, stop all nodes
		poolsStillRunning := false
		for _, pool := range currentConfig.Pools {
			if !pool.IsJobGenerationDone() || pool.GetNumberOfAllJobs() > 0 {
				poolsStillRunning = true
			} else {
				pool.StopAllNodes()
			}
		}
		if poolsStillRunning {
			continue mainloop
		}
		// "Fix" rare situations where server is stopped before node received the message to shut down
		time.Sleep(500 * time.Millisecond)
		// After all nodes are stopped ...
		for _, pool := range currentConfig.Pools {
			if !pool.NodesEmpty() {
				continue mainloop
			}
		}
		// "Fix" rare situations where server is stopped before node received the message to shut down
		time.Sleep(500 * time.Millisecond)

		log.WithFields(log.Fields{
			"module": "core.server",
			"src":    "server",
		}).Info("Closing event handlers")
		// ... and event handlers are closed ...
		currentConfig.CloseEventHandlers()
		// ... finally stop the server by ending its main loop
		break mainloop
	}
}

// SendMessage takes a socket and a servermessage that is going to be sent on the socket
func SendMessage(sock mangos.Socket, message *nraySchema.NrayServerMessage) {
	marshalled, err := proto.Marshal(message)
	utils.CheckError(err, false)
	err = sock.Send(marshalled)
	utils.CheckError(err, false)
}

func initPools() {
	statusInterval := externalConfig.GetDuration("statusPrintInterval")
	for i := 0; i < externalConfig.GetInt("pools"); i++ {
		CurrentConfig.Pools[i] = initPool(statusInterval)
	}

	// Create goroutines that clean up pools regularly
	nodeExpiryTime := time.Duration(externalConfig.GetInt("internal.nodeExpiryTime")) * time.Second
	nodeExpiryCheckInterval := time.Duration(externalConfig.GetInt("internal.nodeExpiryCheckInterval")) * time.Second
	for _, pool := range CurrentConfig.Pools {
		go removeExpiredNodes(pool, nodeExpiryCheckInterval, nodeExpiryTime)
	}

	for _, pool := range CurrentConfig.Pools {
		// Each pool has a target generator
		targetGenerator := targetgeneration.TargetGenerator{}
		targetGenerator.Init(externalConfig.Sub("targetgenerator"))
		pool.TargetChan = targetGenerator.GetTargetChan()
		pool.SetTargetCount(targetGenerator.TargetCount())

		// This goroutine creates jobs for each pool
		go func(p *Pool) {
			log.WithFields(log.Fields{
				"module": "core.server",
				"src":    "initPools",
			}).Debug("Started job creation goroutine")
			for {
				waitingJobs := p.GetNumberOfWaitingJobs()
				// If there are less than 50 jobs, create new ones. I doubt somebody is ever performing a scan at a scale where 50 is too few
				if waitingJobs < 50 {
					nexTarget, ok := <-p.TargetChan
					if ok {
						nextJob := createJob(nexTarget)
						p.AddJobToJobArea(&nextJob)
					} else {
						p.SetJobGenerationDone()
						return
					}
				} else {
					time.Sleep(1 * time.Second)
				}
			}
		}(pool)
	}
}

func checkNodeIDIsRegistered(nodeID string) bool {
	return CurrentConfig.getNodeFromID(nodeID) != nil
}

func startSignalInterruptHandler() {
	// Make a channel to receive interrupt signals ("Ctrl+C")
	interruptSignals := make(chan os.Signal, 1)
	signal.Notify(interruptSignals, os.Interrupt)
	// A goroutine is constantly watching the channel for any incoming signals
	go func(c chan os.Signal) {
		// count the signals.
		// 0: all good
		// 1: send stop to nodes
		// 2: warn user that shutting down nodes may be a good idea and to be patient. really
		// 3: user REALLY wants to exit the server, let's do him a favor...
		ctr := 0
		for sig := range c {
			ctr++
			log.WithFields(log.Fields{
				"module": "core.server",
				"src":    "startSignalInterruptHandler",
			}).Warningf("Caught signal %s", sig)
			if ctr == 1 {
				go func() {
					for _, pool := range CurrentConfig.Pools {
						pool.StopAllNodes()
					waitingTillAllNodesAreGone:
						for {
							log.WithFields(log.Fields{
								"module": "core.server",
								"src":    "startSignalInterruptHandler",
							}).Warning("Stopping all nodes, this may take a few seconds. Please be patient.")
							for _, pool := range CurrentConfig.Pools {
								if !pool.NodesEmpty() {
									// Don't go wild on printing
									time.Sleep(1 * time.Second)
									continue waitingTillAllNodesAreGone
								}
							}
							log.WithFields(log.Fields{
								"module": "core.server",
								"src":    "startSignalInterruptHandler",
							}).Info("All nodes stopped. Now stopping event handlers")
							CurrentConfig.CloseEventHandlers()
							log.WithFields(log.Fields{
								"module": "core.server",
								"src":    "startSignalInterruptHandler",
							}).Info("Event handlers stopped. Exiting now.")
							os.Exit(1)
						}
					}
				}()
			} else if ctr == 2 {
				log.WithFields(log.Fields{
					"module": "core.server",
					"src":    "startSignalInterruptHandler",
				}).Warning("So you really want to exit, I got it... Do you really want to leave zombie scanners around?!")
			} else if ctr == 3 {
				log.WithFields(log.Fields{
					"module": "core.server",
					"src":    "startSignalInterruptHandler",
				}).Warning("You're the boss...")
				os.Exit(1)
			} else {
				log.WithFields(log.Fields{
					"module": "core.server",
					"src":    "startSignalInterruptHandler",
				}).Error("How did you manage to get here?!")
				os.Exit(1)
			}
		}
	}(interruptSignals)
}
