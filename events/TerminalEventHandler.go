package events

import (
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// TerminalEventHandler prints result to stdout
type TerminalEventHandler struct {
	eventChan   chan string
	eventFilter map[string]interface{}
}

// Configure does currently nothing as there is nothing to configure yet
func (t *TerminalEventHandler) Configure(config *viper.Viper) error {
	t.eventChan = make(chan string, config.GetInt("internal.channelsize"))
	t.eventFilter = config.GetStringMap("filter")
	go t.startEventPrinter()
	log.WithFields(log.Fields{
		"module": "events.TerminalEventHandler",
		"src":    "Configure",
	}).Debug("Started TerminalEventHandler")
	return nil
}

// ProcessEvents logs all events to stdout
func (t *TerminalEventHandler) ProcessEvents(events []*nraySchema.Event) {
	go func(events []*nraySchema.Event) {
		for _, event := range events {
			serialized, err := protomarshaller.MarshalToString(event)
			utils.CheckError(err, false)
			t.eventChan <- string(serialized)
		}
	}(events)
}

// ProcessEventStream works like ProcessEvents but reads events from a stream
func (t *TerminalEventHandler) ProcessEventStream(eventStream <-chan *nraySchema.Event) {
	log.WithFields(log.Fields{
		"module": "events.TerminalEventHandler",
		"src":    "ProcessEventStream",
	}).Debug("Processing Event Stream")
	for event := range eventStream {
		serialized, err := protomarshaller.MarshalToString(event)
		utils.CheckError(err, false)
		t.eventChan <- string(serialized)
	}
}

// Close has to do nothing since no output channel has to be closed
func (t *TerminalEventHandler) Close() error {
	return nil
}

func (t *TerminalEventHandler) startEventPrinter() {
	log.WithFields(log.Fields{
		"module": "events.TerminalEventHandler",
		"src":    "startEventPrinter",
	}).Debug("Starting event printer")
	for {
		event, more := <-t.eventChan
		if more {
			if len(t.eventFilter) > 0 {
				for filter, value := range t.eventFilter {
					if FilterMatchesEvent(event, filter, value) {
						log.Infof("Event: %s", event)
						break
					}
				}
			} else {
				log.Infof("Event: %s", event)
			}
		} else {
			return
		}
	}
}
