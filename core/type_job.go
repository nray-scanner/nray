package core

import (
	"sync/atomic"
	"time"

	targetgeneration "github.com/nray-scanner/nray/core/targetGeneration"
)

var globalJobCounter uint64 = 1

// JobState defines the state a Job is currently in
type JobState int

const (
	waiting JobState = iota
	inProgress
)

// Job keeps the state regarding work items
type Job struct {
	id                 uint64
	workItems          targetgeneration.AnyTargets
	state              JobState
	started            time.Time
	nodeIDWorkingOnJob string
	timedOutCounter    uint
}

func createJob(target targetgeneration.AnyTargets) Job {
	// Atomically increment counter and generate our own ID in one step:
	nextID := atomic.AddUint64(&globalJobCounter, 1) - 1
	job := Job{
		id:        nextID,
		workItems: target,
		state:     waiting,
	}
	return job
}
