package core

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	targetgeneration "github.com/nray-scanner/nray/core/targetGeneration"
	"github.com/spf13/viper"

	"github.com/denisbrodbeck/machineid"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	mangos "nanomsg.org/go/mangos/v2"
)

func generateRandomNodeID() string {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	utils.CheckError(err, true)
	return hex.EncodeToString(bytes)
}

// Handles incoming registration requests from nodes
// 1. Check if node is already registered
// 2. If not, generate ID, register it and prepare answer with current time (for node sync)
func handleNodeRegister(message *nraySchema.NodeRegister, considerClientPoolPreference bool, allowMultipleNodesPerHost bool) *nraySchema.RegisteredNode {
	var nodeIDReply string
	// The node already exists and multiple nodes are not allowed. Send empty string
	if !allowMultipleNodesPerHost && CurrentConfig.getNodeFromID(message.GetMachineID()) != nil {
		nodeIDReply = ""
		log.WithFields(log.Fields{
			"module": "core.messageStuff",
			"src":    "handleNodeRegister",
		}).Debugf("Node with ID %s is already registered, refusing", message.GetMachineID())
	} else {
		var newNodeID string
		if allowMultipleNodesPerHost {
			for {
				newNodeID = generateRandomNodeID()
				// Make sure that the ID is not already assigned
				if CurrentConfig.getNodeFromID(newNodeID) == nil {
					break
				}
			}
		} else {
			newNodeID = message.GetMachineID()
		}
		var targetPool *Pool
		if considerClientPoolPreference && CurrentConfig.getPool(int(message.GetPreferredPool())) != nil {
			targetPool = CurrentConfig.getPool(int(message.GetPreferredPool()))
			log.WithFields(log.Fields{
				"module": "core.messageStuff",
				"src":    "handleNodeRegister",
			}).Debugf("Assigned node %s to pool %d", newNodeID, int(message.GetPreferredPool()))
		} else {
			targetPool = CurrentConfig.getSmallestPool()
		}
		targetPool.addNodeToPool(newNodeID, message.GetPreferredNodeName(), "", time.Now())
		nodeIDReply = newNodeID
		log.WithFields(log.Fields{
			"module": "core.messageStuff",
			"src":    "handleNodeRegister",
		}).Debugf("New node %s registered successfully", newNodeID)
	}
	registeredNode := &nraySchema.RegisteredNode{
		NodeID:      nodeIDReply,
		ServerClock: ptypes.TimestampNow(),
	}
	return registeredNode
}

// HandleRegisteredNode extracts the assigned scanner ID
// as well as the clock offset
func HandleRegisteredNode(registeredNode *nraySchema.RegisteredNode) (string, time.Duration, *viper.Viper) {
	nodeID := registeredNode.GetNodeID()
	log.WithFields(log.Fields{
		"module": "core.messageStuff",
		"src":    "HandleRegisteredNode",
	}).Infof("Got ID: %s", nodeID)
	if nodeID == "" {
		log.WithFields(log.Fields{
			"module": "core.messageStuff",
			"src":    "HandleRegisteredNode",
		}).Error("Aborting, server refused to give an ID. Is there another instance running on this system?")
		os.Exit(1)
	}
	serverTime, err := ptypes.Timestamp(registeredNode.GetServerClock())
	utils.CheckError(err, true)
	timeOffset := serverTime.Sub(time.Now())
	rawConfig := registeredNode.GetScannerconfig()
	utils.CheckError(err, true)
	scannerConfig := viper.New()
	scannerConfig.SetConfigType("json")
	scannerConfig.ReadConfig(bytes.NewBuffer(rawConfig))
	return nodeID, timeOffset, scannerConfig
}

func handleHeartbeat(heartbeat *nraySchema.Heartbeat) *nraySchema.HeartbeatAck {
	id := heartbeat.NodeID
	timestamp, err := ptypes.Timestamp(heartbeat.BeatTime)
	utils.CheckError(err, false)
	// Timestamp mustn't be older than 10 seconds
	diff := time.Now().Sub(timestamp)
	if diff.Seconds() > 10 {
		log.WithFields(log.Fields{
			"module": "core.messageStuff",
			"src":    "handleHeartbeat",
		}).Debug("Received too old heartbeat, temporarily stopping scanner")
		return &nraySchema.HeartbeatAck{
			Running:  true,
			Scanning: false,
		}
	}
	pool := CurrentConfig.getPoolFromNodeID(id)
	if pool == nil {
		log.WithFields(log.Fields{
			"module": "core.messageStuff",
			"src":    "handleHeartbeat",
		}).Error("Pool is nil, this should not happen. Probably I'm going to die right now.")
	}
	pool.updateHeartbeatTimer(id, timestamp)
	node := CurrentConfig.getNodeFromID(id)
	log.WithFields(log.Fields{
		"module": "core.messageStuff",
		"src":    "handleHeartbeat",
	}).Debugf("Received heartbeat %v from node %s", timestamp, node.Name)
	// No more jobs, stop node
	if pool.IsJobGenerationDone() && pool.GetNumberOfWaitingJobs() == 0 {
		node.setStop(true)
	}

	return &nraySchema.HeartbeatAck{
		Running:  !node.getStop(),
		Scanning: !node.scanPaused,
	}
}

func handleMoreWorkRequest(moreWork *nraySchema.MoreWorkRequest) string {
	return moreWork.NodeID
}

func createMoreWorkMsg(targets targetgeneration.AnyTargets, jobID uint64) []byte {
	t := &nraySchema.ScanTargets{
		Rhosts:   targets.RemoteHosts,
		Tcpports: targets.TCPPorts,
		Udpports: targets.UDPPorts,
	}
	moreWork := &nraySchema.MoreWorkReply{
		Batchid: jobID,
		Targets: t,
	}
	serverMessage := &nraySchema.NrayServerMessage{
		MessageContent: &nraySchema.NrayServerMessage_JobBatch{
			JobBatch: moreWork,
		},
	}
	marshalled, err := proto.Marshal(serverMessage)
	utils.CheckError(err, false)
	return marshalled
}

func createUnregisteredMessage(nodeID string) *nraySchema.NrayServerMessage {
	return &nraySchema.NrayServerMessage{
		MessageContent: &nraySchema.NrayServerMessage_NodeIsUnregistered{
			NodeIsUnregistered: &nraySchema.Unregistered{
				NodeID: nodeID,
			},
		},
	}
}

// makeHeartbeats sends an already serialized heartbeat every heartBeatTick to the specified channel
func makeHeartbeats(dataChan chan<- *nraySchema.NrayNodeMessage, heartBeatTick time.Duration, timeOffset time.Duration) {
	ticker := time.NewTicker(heartBeatTick)
	for range ticker.C {
		// Add offset to have timestamps aligned to the server's clock
		normalizedTime, err := ptypes.TimestampProto(time.Now().Add(timeOffset))
		utils.CheckError(err, false)
		heartbeat := nraySchema.Heartbeat{
			NodeID:   nodeID,
			BeatTime: normalizedTime,
		}
		msg := &nraySchema.NrayNodeMessage{
			MessageContent: &nraySchema.NrayNodeMessage_Heartbeat{
				Heartbeat: &heartbeat,
			},
		}
		dataChan <- msg
	}
}

// Generate an already serialized NodeRegister message
func generateNodeRegister(nodeName string, preferredPool int32) []byte {
	// the machineid is supposed to be a unique machine
	// identifier, so the server is able to reject multiple
	// instances running on the same machine
	id, err := machineid.ProtectedID("nray-scanner")
	utils.CheckError(err, false)
	if err != nil || len(id) < 8 {
		log.WithFields(log.Fields{
			"module": "core.messagestuff",
			"src":    "generateNodeRegister",
		}).Warningf("Some error occured during generation of node ID. Falling back to random node IDs.")
		id = generateRandomNodeID()
	}
	envInfo := gatherEnvironmentInformation()
	event := &nraySchema.Event{
		NodeID:      id[0:8],
		NodeName:    nodeName,
		Scannername: "node_environment",
		EventData: &nraySchema.Event_Environment{
			Environment: envInfo,
		},

		Timestamp: ptypes.TimestampNow(),
	}
	node := nraySchema.NodeRegister{
		MachineID:         id[0:8],
		PreferredNodeName: nodeName,
		PreferredPool:     preferredPool,
		Envinfo:           event,
	}
	nodeMessage := &nraySchema.NrayNodeMessage{
		MessageContent: &nraySchema.NrayNodeMessage_NodeRegister{
			NodeRegister: &node,
		},
	}
	msg, err := proto.Marshal(nodeMessage)
	utils.CheckError(err, true)
	return msg
}

// HandleHeartbeatAck unpacks the message and returns the values
func HandleHeartbeatAck(heartbeatAck *nraySchema.HeartbeatAck) (bool, bool) {
	return heartbeatAck.Scanning, heartbeatAck.Running
}

// Register a node at the server. The node generates a unique ID
// that identifies the machine so the server can reject multiple
// instances on the same machine
func registerNode(sock mangos.Socket, nodeName string, preferredPool int32) (string, time.Duration, error) {
	err := sock.Send(generateNodeRegister(nodeName, preferredPool))
	utils.CheckError(err, true)
	msg, err := sock.Recv()
	utils.CheckError(err, true)
	// Unpack it
	skeleton := &nraySchema.NrayServerMessage{}
	err = proto.Unmarshal(msg, skeleton)
	utils.CheckError(err, false)

	// Depending on the content of the message, do someting
	switch skeleton.MessageContent.(type) {
	case *nraySchema.NrayServerMessage_RegisteredNode:
		nodeID, timeOffset, scannerConfig = HandleRegisteredNode(skeleton.GetRegisteredNode())
		return nodeID, timeOffset, nil
	case nil:
		return "", 0, fmt.Errorf("Expected RegisteredNode message")
	default:
		return "", 0, fmt.Errorf("Expected RegisteredNode message")
	}
}
