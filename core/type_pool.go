package core

import (
	"fmt"
	"sync"
	"time"

	targetgeneration "github.com/nray-scanner/nray/core/targetGeneration"
	log "github.com/sirupsen/logrus"
)

// Pool is a container that contains nodes and
// work those nodes have still to do
type Pool struct {
	nodeLock                    sync.RWMutex
	nodes                       map[string]*Node
	TargetChan                  <-chan targetgeneration.AnyTargets
	targetGenerationErrorStream chan error
	jobArea                     []*Job
	jobAreaLock                 sync.Mutex
	jobGenerationDone           bool
	jobGenerationDoneLock       sync.RWMutex
	CountTargets                uint64
	CountWorkDone               uint64
	poolLock                    sync.RWMutex
}

// Returns a pointer to a newly allocated pool
func initPool(statusInterval time.Duration) *Pool {
	p := &Pool{
		nodes:                       make(map[string]*Node, 0),
		TargetChan:                  make(chan targetgeneration.AnyTargets, 1024),
		targetGenerationErrorStream: make(chan error, 100),
		jobArea:                     make([]*Job, 0),
		jobGenerationDone:           false,
	}
	go p.printProgress(statusInterval)
	return p
}

func (p *Pool) getCurrentPoolSize() int {
	p.nodeLock.RLock()
	defer p.nodeLock.RUnlock()
	poolSize := len(p.nodes)
	return poolSize
}

// Returns a pointer to the node with the given ID - if the node didn't exist, the second return value is false
func (p *Pool) getNodeFromID(searchID string) (*Node, bool) {
	p.nodeLock.RLock()
	defer p.nodeLock.RUnlock()
	node, exists := p.nodes[searchID]
	return node, exists
}

// Adds a new node to the pool
func (p *Pool) addNodeToPool(newNodeID string, newNodeName string, newNodeMetaInfo string, newNodeRegisterTime time.Time) {
	var finalNodeName string
	// if no name is presented, take node ID as name
	if newNodeName == "" {
		finalNodeName = newNodeID
	} else {
		finalNodeName = newNodeName
	}
	newNode := Node{
		ID:            newNodeID,
		Name:          finalNodeName,
		MetaInfo:      newNodeMetaInfo,
		LastHeartbeat: newNodeRegisterTime,
	}
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	p.nodes[newNodeID] = &newNode
}

// Removes a node from the pool
func (p *Pool) removeNodeFromPool(nodeID string, kill bool) bool {
	if !kill {
		if p.NodeHasOpenJobs(nodeID) {
			return false
		}
	} else {
		p.jobAreaLock.Lock()
		defer p.jobAreaLock.Unlock()
		for _, job := range p.jobArea {
			if job.nodeIDWorkingOnJob == nodeID {
				job.nodeIDWorkingOnJob = ""
				job.state = waiting
			}
		}
	}
	// Don't use getNodeFromID() here since an atomar locking is required for the whole operation
	// Otherwise it might be possible that other goroutines are modifying the slice between
	// getting the index and deleting it
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	delete(p.nodes, nodeID)
	return true
}

// Returns a list of nodes that are expired
func (p *Pool) getExpiredNodeIDs(expiryTime time.Duration) []string {
	expiredNodeIDs := make([]string, 0)
	p.nodeLock.RLock()
	defer p.nodeLock.RUnlock()
	for _, node := range p.nodes {
		if time.Now().Sub(node.LastHeartbeat) > expiryTime {
			expiredNodeIDs = append(expiredNodeIDs, node.ID)
		}
	}
	return expiredNodeIDs
}

// Deletes a node from the pool
func (p *Pool) updateHeartbeatTimer(nodeID string, lastHeartbeatReceived time.Time) {
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	node, exists := p.nodes[nodeID]
	if exists {
		node.heartBeatLock.Lock()
		defer node.heartBeatLock.Unlock()
		node.LastHeartbeat = lastHeartbeatReceived
	}
}

// Supposed to run in a dedicated goroutine
func removeExpiredNodes(pool *Pool, checkInterval time.Duration, maxExpiryTime time.Duration) {
	ticker := time.NewTicker(checkInterval)
	for range ticker.C {
		expiredNodes := pool.getExpiredNodeIDs(maxExpiryTime)
		for _, nodeID := range expiredNodes {
			log.WithFields(log.Fields{
				"module": "core.type_pool",
				"src":    "removeExpiredNodes",
			}).Debugf("Removing node %s from pool", nodeID)
			pool.removeNodeFromPool(nodeID, true)
		}
	}
}

func (p *Pool) removeJobFromJobArea(nodeID string, jobIDToDelete uint64) error {
	p.jobAreaLock.Lock()
	defer p.jobAreaLock.Unlock()
	posOfJobToDelete := -1
	workDoneCount := uint64(0)
	// Locate Job
	for pos, job := range p.jobArea {
		if job.id == jobIDToDelete && job.nodeIDWorkingOnJob == nodeID {
			posOfJobToDelete = pos
			workDoneCount = job.workItems.TargetCount()
			break
		}
	}

	if posOfJobToDelete == -1 {
		return fmt.Errorf("Couldn't find the job to delete")
	}

	// Enter the madness
	// https://github.com/golang/go/wiki/SliceTricks
	p.jobArea[posOfJobToDelete] = p.jobArea[len(p.jobArea)-1]
	p.jobArea[len(p.jobArea)-1] = nil
	p.jobArea = p.jobArea[:len(p.jobArea)-1]

	p.poolLock.Lock()
	p.CountWorkDone += workDoneCount
	p.poolLock.Unlock()
	return nil
}

// GetJobForNode returns the next job for a given node ID
func (p *Pool) GetJobForNode(nodeID string) *Job {
	p.jobAreaLock.Lock()
	defer p.jobAreaLock.Unlock()
	for _, job := range p.jobArea {
		if job.nodeIDWorkingOnJob == nodeID {
			return job

		}
	}
	for _, job := range p.jobArea {
		if job.nodeIDWorkingOnJob == "" {
			job.nodeIDWorkingOnJob = nodeID
			job.state = inProgress
			return job
		}
	}
	return nil
}

// GetNumberOfWaitingJobs returns how many jobs are currently open
func (p *Pool) GetNumberOfWaitingJobs() int {
	p.jobAreaLock.Lock()
	defer p.jobAreaLock.Unlock()
	// Count waiting jobs
	waitingJobs := 0
	for _, job := range p.jobArea {
		if job.state == waiting {
			waitingJobs++
		}
	}
	return waitingJobs
}

// GetNumberOfAllJobs returns the length of the JobArea. If it is
// 0, we can likely stop all nodes and the server
func (p *Pool) GetNumberOfAllJobs() int {
	p.jobAreaLock.Lock()
	defer p.jobAreaLock.Unlock()
	return len(p.jobArea)
}

// AddJobToJobArea adds a new job to this pool's job queue
func (p *Pool) AddJobToJobArea(job *Job) {
	p.jobAreaLock.Lock()
	defer p.jobAreaLock.Unlock()
	p.jobArea = append(p.jobArea, job)
}

// SetJobGenerationDone sets the flag that job generation is done
func (p *Pool) SetJobGenerationDone() {
	p.jobGenerationDoneLock.Lock()
	defer p.jobGenerationDoneLock.Unlock()
	p.jobGenerationDone = true
}

// IsJobGenerationDone queries the flag indicating that all jobs were generated
func (p *Pool) IsJobGenerationDone() bool {
	p.jobGenerationDoneLock.RLock()
	defer p.jobGenerationDoneLock.RUnlock()
	return p.jobGenerationDone
}

// StopNode pauses a single node identified by its ID
func (p *Pool) StopNode(nodeID string) {
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	for _, node := range p.nodes {
		if node.ID == nodeID {
			node.setStop(true)
		}
	}
}

// StopAllNodes pauses all nodes in this pool
func (p *Pool) StopAllNodes() {
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	for _, node := range p.nodes {
		node.setStop(true)
	}
}

// ResumeNode resumes a single node identified by its ID
func (p *Pool) ResumeNode(nodeID string) {
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	for _, node := range p.nodes {
		if node.ID == nodeID {
			node.setStop(false)
		}
	}
}

// ResumeAllNodes resumes all nodes in this pool
func (p *Pool) ResumeAllNodes() {
	p.nodeLock.Lock()
	defer p.nodeLock.Unlock()
	for _, node := range p.nodes {
		node.setStop(false)
	}
}

// NodeHasOpenJobs returns true if the node did not finish
// all of its jobs, false otherwise
func (p *Pool) NodeHasOpenJobs(nodeID string) bool {
	p.jobAreaLock.Lock()
	defer p.jobAreaLock.Unlock()
	for _, job := range p.jobArea {
		if job.nodeIDWorkingOnJob == nodeID {
			return true
		}
	}
	return false
}

// NodesEmpty returns true if there are no nodes left in the pool
func (p *Pool) NodesEmpty() bool {
	p.nodeLock.RLock()
	defer p.nodeLock.RUnlock()
	return len(p.nodes) == 0
}

func (p *Pool) printProgress(pause time.Duration) {
	ticker := time.NewTicker(pause)
	for {
		_ = <-ticker.C
		p.poolLock.RLock()
		done := p.CountWorkDone
		all := p.CountTargets
		p.poolLock.RUnlock()
		ratio := float32(0)
		if all != 0 && all >= done {
			ratio = float32(done) / float32(all)
		}
		log.WithFields(log.Fields{
			"module": "core.type_pool",
			"src":    "printProgress",
		}).Infof("All: %d; TODO: %d; Done: %d (%.2f%%)", all, all-done, done, ratio*100)
	}
}

// SetTargetCount is goroutine safe for setting the target count
func (p *Pool) SetTargetCount(targetCount uint64) {
	p.poolLock.Lock()
	defer p.poolLock.Unlock()
	p.CountTargets = targetCount
}
