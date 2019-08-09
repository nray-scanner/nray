package core

import (
	"crypto/tls"

	"github.com/nray-scanner/nray/events"
	nraySchema "github.com/nray-scanner/nray/schemas"
)

// GlobalConfig holds configuration settings
// that are relevant for the operation of the
// core
type GlobalConfig struct {
	ListenPorts   []uint32
	ListenHost    string
	TLSConfig     *tls.Config
	Pools         []*Pool
	EventHandlers []events.EventHandler
}

// Returns a pointer to the node with the given ID
func (gc GlobalConfig) getNodeFromID(searchID string) *Node {
	for _, pool := range gc.Pools {
		if node, exists := pool.getNodeFromID(searchID); exists {
			return node
		}
	}
	return nil
}

func (gc GlobalConfig) getPoolFromNodeID(searchID string) *Pool {
	for _, pool := range gc.Pools {
		if _, exists := pool.getNodeFromID(searchID); exists {
			return pool
		}
	}
	return nil
}

func (gc GlobalConfig) getPool(poolID int) *Pool {
	if poolID > 0 && len(gc.Pools) > poolID {
		return gc.Pools[poolID]
	}
	return nil
}

// Returns a pointer to the pool with the fewest members
func (gc GlobalConfig) getSmallestPool() *Pool {
	size := 0
	var smallest *Pool
	for _, pool := range gc.Pools {
		// In case we have no smallest yet, initialise it with the first pool
		if smallest == nil {
			smallest = pool
			size = pool.getCurrentPoolSize()
		} else if thisPoolSize := pool.getCurrentPoolSize(); thisPoolSize < size {
			smallest = pool
			size = thisPoolSize
		}
	}
	return smallest
}

// LogEvents sends a slice of events to all registered event handlers
func (gc GlobalConfig) LogEvents(events []*nraySchema.Event) {
	for _, handler := range gc.EventHandlers {
		handler.ProcessEvents(events)
	}
}

// CloseEventHandlers calls Close() on all registered event handlers
func (gc GlobalConfig) CloseEventHandlers() {
	for _, eventHandler := range gc.EventHandlers {
		eventHandler.Close()
	}
}
