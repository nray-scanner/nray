package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
)

var internalTimeOffset time.Duration

func currentTime() time.Time {
	return time.Now().Add(internalTimeOffset)
}

// RunNodeScannerLoop orchestrates the actual scanning. It knows when to request work and how to perform
// communication between which scanning components
// pause is only used for controlling the scanning, so pause/continue can be supported. Reading/writing to it has to be synchronized
// The workbatch channel is used to send workbatches
// Data sent to dataChan will be picked by the nodes send/recv loop and transferred to the server,
// so it is used for sending requests for more work or reporting results
// TODO: Scan options
func RunNodeScannerLoop(controller *ScanController, workBatchChan <-chan *nraySchema.MoreWorkReply, dataChan chan<- *nraySchema.NrayNodeMessage) {
	var tcpscanner = &TCPScanner{}
	var udpscanner = &UDPScanner{}
	tcpscanner.Configure(controller.scannerConfig.Sub("tcp")) // TODO: actual configuration and create struct via New()
	udpscanner.Configure(controller.scannerConfig.Sub("udp"))
	for {
		// if the scan is paused, sleep 2 seconds before checking again
		if controller.Pause.GetValue() {
			time.Sleep(2 * time.Second)
			continue
		}

		// Get more work
		log.WithFields(log.Fields{
			"module": "scanner.scanner",
			"src":    "RunNodeScannerLoop",
		}).Info("Requesting work batch")
		dataChan <- requestBatch(controller.nodeID)

		// Get the work
		workBatch := <-workBatchChan
		if workBatch.Batchid == 0 { // Server has no work yet, sleep 2s
			time.Sleep(time.Second * 2)
			continue
		}

		controller.Refresh() // Resets internal channels and starts house keeping goroutines

		// Spin up workers
		// Each worker has access to ScanController's work queue
		// Work queue contains functions that are fully prepared, this means they
		// have full state regarding targets, timeouts, configuration, where and how
		// to report. Workers are just here to control the level of concurrency
		var wg sync.WaitGroup
		log.WithFields(log.Fields{
			"module": "scanner.scanner",
			"src":    "RunNodeScannerLoop",
		}).Debugf("Starting workers: %d", controller.scannerConfig.GetInt("workers"))
		for i := 0; i < controller.scannerConfig.GetInt("workers"); i++ {
			wg.Add(1)
			go func(queue <-chan func()) {
				for queuedTask := range queue {
					atomic.AddInt64(&controller.scansRunning, 1)
					controller.ratelimiter.Wait(context.TODO())
					queuedTask()
					atomic.AddInt64(&controller.scansRunning, -1)
				}
				wg.Done()
			}(controller.scanQueue)
		}

		for scanFunc := range PrepareScanFuncs(tcpscanner, udpscanner, workBatch, controller.portscanResultQueue) {
			controller.scanQueue <- scanFunc
		}

		go controller.waitForScanToFinishAndEventsToBeProcessed()

		// STEPS

		// 1: Register modules (in scannernode.go)
		// 2: Implement abstract port scanning
		// 2.1: message format should also support stuff like networks (for ZMAP)
		// 2.2: which port scanner to chose is definied in the controller (see comment above)
		// 3: Port scan results are sent to controller
		// 4: Controller parses results and creates/forwards events to send them upstream
		// 5: Controller triggers higher level scanners to do their job
		// 6: Done when
		// 6.1: Port scanner is done AND
		// 6.2: No higher level scans are queued (queue should be empty)
		// 6.3: All higher level scans have been performed (use a semaphore for counting active tasks?)

		wg.Wait()
		controller.workersDone = true
		close(controller.portscanResultQueue)
		dataChan <- reportResults(controller.nodeID, workBatch.Batchid, controller.getResults())
	}
}

// build a MoreWorkRequest and return the serialized message
func requestBatch(id string) *nraySchema.NrayNodeMessage {
	workRequest := nraySchema.MoreWorkRequest{
		NodeID: id,
	}
	message := &nraySchema.NrayNodeMessage{
		MessageContent: &nraySchema.NrayNodeMessage_MoreWork{
			MoreWork: &workRequest,
		},
	}
	return message
}

// send the collected results to the server
func reportResults(nodeID string, batchID uint64, events []*nraySchema.Event) *nraySchema.NrayNodeMessage {
	workDone := nraySchema.WorkDone{
		NodeID:  nodeID,
		Batchid: batchID,
		Events:  events,
	}
	message := &nraySchema.NrayNodeMessage{
		MessageContent: &nraySchema.NrayNodeMessage_WorkDone{
			WorkDone: &workDone,
		},
	}
	return message
}

// PrepareScanFuncs returns a channel where scan functions are sent over
// They are completely prepared and just have to be called
func PrepareScanFuncs(tcpscanner *TCPScanner, udpscanner *UDPScanner, targetMsg *nraySchema.MoreWorkReply, results chan<- *PortscanResult) <-chan func() {
	scanFuncs := make(chan func(), 100)

	go func(targetMsg *nraySchema.MoreWorkReply, results chan<- *PortscanResult) {
		for _, target := range targetMsg.Targets.GetRhosts() {
			for _, targetTCPPort := range targetMsg.Targets.GetTcpports() {
				// Reassign variables in new scope to avoid data race
				t := target
				port := targetTCPPort
				timeout := tcpscanner.timeout
				scanFuncs <- func() {
					result, err := tcpConnectIsOpen(t, port, timeout)
					utils.CheckError(err, false)
					results <- result
				}
			}
			for _, targetUDPPort := range targetMsg.Targets.GetUdpports() {
				t := target
				port := targetUDPPort
				scanFuncs <- func() {
					result, err := udpProtoScan(t, port, *udpscanner)
					utils.CheckError(err, false)
					results <- result
				}
			}
		}
		close(scanFuncs)
	}(targetMsg, results)

	return scanFuncs
}
