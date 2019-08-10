package events

import (
	"fmt"
	"os"
	"sync"
	"time"

	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// JSONFileEventHandler implements the EventHandler interface and writes
// events to a file
type JSONFileEventHandler struct {
	filedescriptor *os.File
	eventChan      chan string
	flushChan      chan bool
	eventFilter    map[string]interface{}
	waitgroup      sync.WaitGroup
}

// Configure takes a viper configuration for this event handler and reads the following values:
// filename: Where to store the file
// internal.channelsize: the size of the internally used buffering channel
// internal.synctimer: intervall to periodically flush events in seconds.
func (handler *JSONFileEventHandler) Configure(config *viper.Viper) error {
	var err error
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "Configure",
	}).Debug("Checking if filedescriptor already exists")
	if handler.filedescriptor != nil {
		log.Debug("File descriptor already exists, returning an error")
		return fmt.Errorf("This EventHandler is already configured")
	}
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "Configure",
	}).Debugf("Opening file: %s", config.GetString("filename"))
	mode := os.O_RDWR | os.O_CREATE | os.O_EXCL
	if config.GetBool("overwriteExisting") {
		mode = os.O_RDWR | os.O_CREATE
	}
	handler.filedescriptor, err = os.OpenFile(config.GetString("filename"), mode, 0644)
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "Configure",
	}).Debug("Creating channels")
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "Configure",
	}).Debugf("Event channel size is going to be %d", config.GetInt("internal.channelsize"))
	handler.eventChan = make(chan string, config.GetInt("internal.channelsize"))
	handler.flushChan = make(chan bool)
	handler.eventFilter = config.GetStringMap("filter")
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "Configure",
	}).Debug("Starting goroutines")
	go handler.startFlushTicker(config.GetDuration("internal.synctimer"))
	go handler.startEventWriter()
	return nil
}

// ProcessEvents takes a pointer to an array with events and passes them
// to the internal processing
func (handler *JSONFileEventHandler) ProcessEvents(events []*nraySchema.Event) {
	go func(events []*nraySchema.Event) {
		handler.waitgroup.Add(1)
		for _, event := range events {
			serialized, err := protomarshaller.MarshalToString(event)
			utils.CheckError(err, false)
			handler.eventChan <- serialized
		}
		handler.waitgroup.Done()
	}(events)
}

// ProcessEventStream takes a channel, reads the events and sends them to the internal
// processing where they are written. This function is useful for running in a dedicated
// goroutine
func (handler *JSONFileEventHandler) ProcessEventStream(eventStream <-chan *nraySchema.Event) {
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "ProcessEventStream",
	}).Debug("Processing events")
	for event := range eventStream {
		serialized, err := protomarshaller.MarshalToString(event)
		utils.CheckError(err, false)
		handler.eventChan <- serialized
	}
}

// Close waits until the events are written and closes the file descriptor
func (handler *JSONFileEventHandler) Close() error {
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "Close",
	}).Debug("Closing EventHandler")
	handler.waitgroup.Wait()
	close(handler.eventChan)
	for len(handler.eventChan) > 0 { // Give time to flush events still in queue
		time.Sleep(100 * time.Millisecond)
	}
	err := handler.filedescriptor.Close()
	return err
}

func (handler *JSONFileEventHandler) startFlushTicker(interval time.Duration) {
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "startFlushTicker",
	}).Debug("Flush ticker started")
	ticker := time.NewTicker(interval)
	for range ticker.C {
		handler.flushChan <- true
	}
}

func (handler *JSONFileEventHandler) startEventWriter() {
	log.WithFields(log.Fields{
		"module": "events.JSONFileEventHandler",
		"src":    "startEventWriter",
	}).Debug("Starting event writer")
	for {
		select {
		case event, more := <-handler.eventChan:
			if more {
				if len(handler.eventFilter) > 0 {
					for filter, value := range handler.eventFilter {
						if FilterMatchesEvent(event, filter, value) {
							handler.filedescriptor.Write([]byte(event))
							handler.filedescriptor.Write([]byte{'\n'})
							break
						}
					}
				} else {
					handler.filedescriptor.Write([]byte(event))
					handler.filedescriptor.Write([]byte{'\n'})
				}
			} else {
				handler.filedescriptor.Write([]byte{'\n'})
				return
			}
		case <-handler.flushChan:
			handler.filedescriptor.Sync()
		}
	}
}
