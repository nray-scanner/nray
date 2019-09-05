package core

import (
	"fmt"
	"os"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/nray-scanner/nray/scanner"
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"

	"github.com/spf13/viper"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"

	// TCP transport for nanomsg
	_ "nanomsg.org/go/mangos/v2/transport/tcp"
	_ "nanomsg.org/go/mangos/v2/transport/tlstcp"
)

// TODO: Get rid of globals / unify them to a struct
var nodeID string
var timeOffset time.Duration
var scannerConfig *viper.Viper

// These variables are currently hardcoded and should be configurable in the future
const sendDeadline = 30 * time.Second
const recvDeadline = 30 * time.Second
const heartBeatTick = 5 * time.Second

// NodeCmdArgs holds user data that is passed on to scanner node
type NodeCmdArgs struct {
	Server                     string
	Port                       string
	Debug                      bool
	PreferredPool              int32
	NodeName                   string
	UseTLS                     bool
	TLSIgnoreServerCertificate bool
	TLSCACertPath              string
	TLSClientKeyPath           string
	TLSClientCertPath          string
	TLSServerSAN               string
}

// RunNode is called by the main function of the node binary and gets everything up and running
func RunNode(args NodeCmdArgs) {
	if args.Debug {
		log.SetLevel(log.DebugLevel)
		log.SetFormatter(&utils.Formatter{})
	}
	// Bring sanity back...
	if len(args.NodeName) > 32 {
		args.NodeName = args.NodeName[:32]
		log.WithFields(log.Fields{
			"module": "core.scannernode",
			"src":    "RunNode",
		}).Debugf("Truncating name to %s", args.NodeName)
	}
	if args.Server == "" {
		log.Printf("Server is not specified, using localhost")
		args.Server = "localhost"
	}
	if args.Port == "" {
		log.Printf("Port is not specified, using 8601")
		args.Port = "8601"
	}

	var socketConfig map[string]interface{}
	socketConfig, err := setupMangosClientTLSConfig(args.UseTLS, args.TLSIgnoreServerCertificate, args.TLSCACertPath,
		args.TLSClientCertPath, args.TLSClientKeyPath, args.TLSServerSAN)
	utils.CheckError(err, true)
	sock := initServerConnection(args.Server, args.Port, socketConfig) // establish network connection to server
	defer sock.Close()

	nodeID, timeOffset, err = registerNode(sock, args.NodeName, args.PreferredPool) // makes node known to server and sets nodeID and timeOffset
	utils.CheckError(err, true)

	// Everything sent to this channel will be sent to the server
	dataChan := make(chan *nraySchema.NrayNodeMessage, 10)
	log.WithFields(log.Fields{
		"module": "core.scannernode",
		"src":    "RunNode",
	}).Debugf("Node name is set to %s", args.NodeName)
	scanController := scanner.CreateScanController(nodeID, args.NodeName, timeOffset, scannerConfig)

	// JobBatches are sent here
	workBatchChan := make(chan *nraySchema.MoreWorkReply)

	// makeHeartbeats runs asynchronously in its own goroutine and sends regular heartbeats
	go makeHeartbeats(dataChan, heartBeatTick, timeOffset)

	// here does the actual scanning work happen
	go scanner.RunNodeScannerLoop(scanController, workBatchChan, dataChan)

	// After the client is registered, this is the main program loop
	// that sends and receives messages and passes them to the appropriate
	// functions
mainloop:
	for {
		// Get message from internal data channel and send it to server
		nextNodeMessage := <-dataChan
		marshalled, err := proto.Marshal(nextNodeMessage)
		utils.CheckError(err, false)
		err = sock.Send(marshalled)
		utils.CheckError(err, false)

		// Receive response
		msg, err := sock.Recv()
		utils.CheckError(err, false)

		// Unpack it
		skeleton := &nraySchema.NrayServerMessage{}
		err = proto.Unmarshal(msg, skeleton)
		utils.CheckError(err, false)

		// Depending on the content of the message, do someting
		switch skeleton.MessageContent.(type) {
		case *nraySchema.NrayServerMessage_RegisteredNode:
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Debug("Register message")
			nodeID, timeOffset, scannerConfig = HandleRegisteredNode(skeleton.GetRegisteredNode())
		case *nraySchema.NrayServerMessage_HeartbeatAck:
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Debug("Heartbeat ACK")
			scanning, running := HandleHeartbeatAck(skeleton.GetHeartbeatAck())
			scanController.Pause.SetValue(!scanning || !running)
			if !running {
				message := &nraySchema.NrayNodeMessage{
					MessageContent: &nraySchema.NrayNodeMessage_Goodbye{
						Goodbye: &nraySchema.Goodbye{
							NodeID: nodeID,
						},
					},
				}
				dataChan <- message
			}
		case *nraySchema.NrayServerMessage_JobBatch:
			b := skeleton.GetJobBatch()
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Debugf("Job Batch with ID %d. It contains %d targets, %d tcp and %d udp ports", b.Batchid, len(b.GetTargets().GetRhosts()), len(b.GetTargets().GetTcpports()), len(b.GetTargets().GetUdpports()))
			workBatchChan <- skeleton.GetJobBatch()
		case *nraySchema.NrayServerMessage_WorkDoneAck:
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Debug("WorkDoneAck")
		case *nraySchema.NrayServerMessage_GoodbyeAck:
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Debug("GoodbyeAck")
			if skeleton.GetGoodbyeAck().Ok {
				log.Debug("Breaking mainloop")
				break mainloop
			}
		case *nraySchema.NrayServerMessage_NodeIsUnregistered:
			nodeID, timeOffset, err = registerNode(sock, args.NodeName, args.PreferredPool)
			utils.CheckError(err, true)
			if _, ok := nextNodeMessage.MessageContent.(*nraySchema.NrayNodeMessage_Heartbeat); ok {
				dataChan <- nextNodeMessage // retransmit the last message unless it was a heartbeat
			}
		case nil:
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Warning("Message sent by server is empty. This should not happen, if you can reproduce this please file a bug report. Continuing operation...")
		default:
			log.WithFields(log.Fields{
				"module": "core.scannernode",
				"src":    "RunNode",
			}).Error("Cannot decode message sent by server")
		}
	}
}

func gatherEnvironmentInformation() *nraySchema.EnvironmentInformation {
	var err error
	var hostname, hostos, processname, username, cpumodelname string
	hostinfo, err := host.Info()
	utils.CheckError(err, false)
	if err != nil {
		hostname = "unknown"
		hostos = "unknown"
	} else {
		hostname = hostinfo.Hostname
		hostos = hostinfo.OS
	}

	pid := os.Getpid()
	proc, err := process.NewProcess(int32(pid))
	utils.CheckError(err, false)
	processname, err = proc.Name()
	utils.CheckError(err, false)
	if err != nil {
		processname = "unknown"
	}
	username, err = proc.Username()
	utils.CheckError(err, false)
	if err != nil {
		username = "unknown"
	}
	cpuinfo, err := cpu.Info()
	utils.CheckError(err, false)
	if err != nil || len(cpuinfo) == 0 {
		cpumodelname = "unknown"
	} else {
		cpumodelname = cpuinfo[0].ModelName
	}

	message := &nraySchema.EnvironmentInformation{
		Hostname:     hostname,
		Os:           hostos,
		Pid:          fmt.Sprintf("%d", pid),
		Processname:  processname,
		Username:     username,
		Cpumodelname: cpumodelname,
	}
	return message
}
