package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/time/rate"

	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/viper"
)

// PauseIndicator is a type that can be used to indicate that a scanner should stop. Concurrency safe.
type PauseIndicator struct {
	scannerShouldPause bool
	lock               sync.RWMutex
}

// SetValue applies the new value
func (pi *PauseIndicator) SetValue(value bool) {
	pi.lock.Lock()
	defer pi.lock.Unlock()
	pi.scannerShouldPause = value
}

// GetValue returns the currently set value
func (pi *PauseIndicator) GetValue() bool {
	pi.lock.RLock()
	defer pi.lock.RUnlock()
	return pi.scannerShouldPause
}

// Target represents one specific target, meaning a service that
// is reachable knowing a proto (TCP/UDP), a destination (FQDN or IP)
// and a port
type Target struct {
	protocol string
	host     string
	port     uint32
}

// ScanTargets allows to abstract different types of target notations
// For regular scans the interface is sufficient, providing
// stream of targets whereas more specific implementations
// may expose data like networks or port ranges directly to
// be more efficient (e.g. when feeding to ZMap)
type ScanTargets interface {
	getTargetGenerator() <-chan *Target // return a channel where Targets are supplied
}

// StandardTargets is the default target implementation that allows for an arbitrary
// *single* host and multiple ports
type StandardTargets struct {
	protocol string
	// url may be a DNS name or IPv4 address WITHOUT protocol or port encoded as string
	url         string
	targetPorts []uint32
}

func (st *StandardTargets) getTargetGenerator() <-chan *Target {
	targetChan := make(chan *Target, len(st.targetPorts))
	go func(proto string, url string, ports []uint32, channel chan<- *Target) {
		for _, port := range ports {
			channel <- &Target{
				protocol: proto,
				host:     url,
				port:     port,
			}
		}
	}(st.protocol, st.url, st.targetPorts, targetChan)
	return targetChan
}

// ScanController holds most information required to keep everything running
type ScanController struct {
	controllerLock sync.RWMutex
	nodeID         string
	nodeName       string
	timeOffset     time.Duration
	scannerConfig  *viper.Viper
	// A map containing functions taking a proto, a host and a port that return
	// a function (closure) that can directly be called. The idea is that each scanner
	// may register itself e.g. for tcp/80 with a function taking those arguments.
	// If tcp/80 is discovered to be open, the function will be called and a closure
	// containing all relevant scanning information is returned. This closure can then
	// be queued in a channel and is picked up by the workers, simply calling the function
	// triggering the scan with the wrapped target information.
	Subscriptions       map[string][]func(proto string, host string, port uint, results chan<- *nraySchema.Event) func()
	subscriptionLock    sync.RWMutex
	Pause               *PauseIndicator
	scanQueue           chan func()
	eventQueue          chan *nraySchema.Event
	portscanResultQueue chan *PortscanResult
	results             []*nraySchema.Event
	resultsLock         sync.Mutex
	workersDone         bool
	ratelimiter         *rate.Limiter
	scansRunning        int64
}

// CreateScanController initialises a ned ScanController
func CreateScanController(nodeID string, nodeName string, timeOffset time.Duration, scannerConfig *viper.Viper) *ScanController {
	if nodeName == "" {
		nodeName = nodeID
	}
	utils.CreateDefaultScannerConfig(scannerConfig)
	sc := &ScanController{
		nodeID:              nodeID,
		nodeName:            nodeName,
		timeOffset:          timeOffset,
		scannerConfig:       scannerConfig,
		Subscriptions:       make(map[string][]func(string, string, uint, chan<- *nraySchema.Event) func()),
		scanQueue:           make(chan func(), 1000),
		eventQueue:          make(chan *nraySchema.Event, 1000),
		portscanResultQueue: make(chan *PortscanResult, 1000),
		results:             make([]*nraySchema.Event, 0),
		workersDone:         false,
		Pause:               &PauseIndicator{scannerShouldPause: false},
		ratelimiter:         rate.NewLimiter(rate.Inf, 1),
		scansRunning:        0,
	}
	requestedZgrab2Modules := scannerConfig.GetStringSlice("zgrab2.enabledModules")
	for _, module := range requestedZgrab2Modules {
		for _, availableModule := range ZGrab2AvailableScanners {
			if module == availableModule {
				zgrab2Scanner := GetZGrab2Scanner(module)
				zgrab2Scanner.Configure(scannerConfig.Sub(fmt.Sprintf("zgrab2.%s", module)), nodeID, nodeName)
				zgrab2Scanner.Register(sc)
				break
			}
		}
	}
	return sc
}

// Refresh cleans the state for each workBatch.
// This is mainly required because termination of each run
// depends heavily on closing internal channels
func (controller *ScanController) Refresh() {
	controller.controllerLock.Lock()
	controller.scanQueue = make(chan func(), 1000)
	controller.eventQueue = make(chan *nraySchema.Event, 1000)
	controller.portscanResultQueue = make(chan *PortscanResult, 1000)
	controller.results = make([]*nraySchema.Event, 0)
	if controller.scannerConfig.GetString("ratelimit") == "none" {
		controller.ratelimiter.SetLimit(rate.Inf)
	} else {
		controller.ratelimiter.SetLimit(rate.Limit(controller.scannerConfig.GetFloat64("ratelimit")))
	}
	controller.controllerLock.Unlock()
	go controller.processPortScanEvents()
	go controller.processEventsToResults()
}

// Subscribe is called by protocol scanners to get notified in case interesting ports are open
func (controller *ScanController) Subscribe(key string, function func(string, string, uint, chan<- *nraySchema.Event) func()) {
	controller.subscriptionLock.Lock()
	defer controller.subscriptionLock.Unlock()
	if controller.Subscriptions[key] == nil {
		controller.Subscriptions[key] = make([]func(string, string, uint, chan<- *nraySchema.Event) func(), 0)
	}
	controller.Subscriptions[key] = append(controller.Subscriptions[key], function)
}

// notifies higher layer scanners that are interested, e.g. if a scanner registered
// for "tcp/80" and such a target is found, the scan function of the higher level
// scanner is prepared and queued here
func (controller *ScanController) notify(proto string, host string, port uint) {
	controller.subscriptionLock.RLock()
	defer controller.subscriptionLock.RUnlock()
	key := fmt.Sprintf("%s/%d", proto, port)
	//log.Debug(key)
	if functions := controller.Subscriptions[key]; functions != nil {
		for _, f := range functions {
			controller.scanQueue <- f(proto, host, port, controller.eventQueue)
		}
	}
}

// processPortScanEvents must run concurrently to a scan in its own goroutine
// It reads the events generated by the port scanner, notifies the higher layer
// scanners and wraps the port scan results into events
func (controller *ScanController) processPortScanEvents() {
	for portscanResult := range controller.portscanResultQueue {
		if portscanResult == nil {
			continue
		}
		// Create Event
		timestamp, _ := ptypes.TimestampProto(currentTime())
		eventData := &nraySchema.Event_Result{
			Result: &nraySchema.ScanResult{
				Target: portscanResult.Target,
				Port:   portscanResult.Port,
				Result: &nraySchema.ScanResult_Portscan{
					Portscan: &nraySchema.PortScanResult{
						Scantype: portscanResult.Scantype,
						Target:   portscanResult.Target,
						Port:     portscanResult.Port,
						Open:     portscanResult.Open,
						Timeout:  uint32(portscanResult.Timeout / time.Millisecond),
					},
				},
			},
		}
		event := &nraySchema.Event{
			NodeID:      controller.nodeID,
			NodeName:    controller.nodeName,
			EventData:   eventData,
			Scannername: "native-portscanner",
			Timestamp:   timestamp,
		}
		controller.eventQueue <- event

		// Notify others
		if portscanResult.Scantype == "tcpconnect" && portscanResult.Open {
			//log.Debug("Notifying: %s:%d", portscanResult.Target, portscanResult.Port)
			controller.notify("tcp", portscanResult.Target, uint(portscanResult.Port))
		}
		if portscanResult.Scantype == "udp" && portscanResult.Open {
			//log.Debug("Notifying: %s:%d", portscanResult.Target, portscanResult.Port)
			controller.notify("udp", portscanResult.Target, uint(portscanResult.Port))
		}
	}
	close(controller.eventQueue)
}

func (controller *ScanController) processEventsToResults() {
	controller.controllerLock.RLock()
	controller.resultsLock.Lock()
	defer controller.controllerLock.RUnlock()
	defer controller.resultsLock.Unlock()
	for event := range controller.eventQueue {
		controller.results = append(controller.results, event)
	}
}

func (controller *ScanController) getResults() []*nraySchema.Event {
	controller.controllerLock.RLock()
	controller.resultsLock.Lock()
	defer controller.controllerLock.RUnlock()
	defer controller.resultsLock.Unlock()
	return controller.results
}

// The only way to find out if a scan is finished is to check if all queues are empty
// Call this function after the workers have finished
func (controller *ScanController) waitForScanToFinishAndEventsToBeProcessed() {
	ctr := 0
	for {
		// Are there any workers having jobs? If no, increment ctr
		if atomic.LoadInt64(&controller.scansRunning) == 0 {
			ctr++
		} else { // Still work, reset ctr
			ctr = 0
		}
		if ctr == 5 { // No work for last 5 probes in 50 ms interval; we're probably done; close chans
			close(controller.scanQueue)
			break
		}

		//log.Debug("sq: %d\t prq: %d\t eq: %d", len(controller.scanQueue), len(controller.portscanResultQueue), len(controller.eventQueue))

		// Check loop runs only all 100 Milliseconds to give producers the chance of filling the queue
		// BTW, weird things happen if you remove this, so don't...
		time.Sleep(100 * time.Millisecond)
	}
}

// TCPPortScanner is the interface all TCP Port Scanners must adhere to
type TCPPortScanner interface {
	Configure(config *viper.Viper)
	PrepareScanFuncs(targetMsg *nraySchema.MoreWorkReply, results chan<- *PortscanResult) <-chan func()
}

// ProtocolScanner is the interface all scanners of higher level protocols must adhere to
// There is no explicit scan method because scanners register themselves for targets of interest
// and are called if something is found
type ProtocolScanner interface {
	Configure(config *viper.Viper, nodeID string, nodeName string)
	Register(scanctrl *ScanController)
}
