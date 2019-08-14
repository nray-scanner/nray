package core

import (
	"sync"
	"time"

	targetgeneration "github.com/nray-scanner/nray/core/targetGeneration"
)

// Node represents relevant information about a node
type Node struct {
	ID            string
	Name          string
	MetaInfo      string
	LastHeartbeat time.Time
	CurrentWork   *targetgeneration.AnyTargets
	heartBeatLock sync.RWMutex
	scanPaused    bool
	stopNode      bool
	stopLock      sync.RWMutex
}

func (node *Node) setStop(value bool) {
	node.stopLock.Lock()
	defer node.stopLock.Unlock()
	node.stopNode = value
}

func (node *Node) getStop() bool {
	node.stopLock.Lock()
	defer node.stopLock.Unlock()
	return node.stopNode
}
