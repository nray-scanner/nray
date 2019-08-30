package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	nraySchema "github.com/nray-scanner/nray/schemas"

	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var elasticBulkActionAndMeta = "{ \"index\" : { \"_index\": \"%s\", \"_type\" : \"_doc\" } }"

// ElasticsearchEventHandler implements the EventHandler interface and writes
// results to an elasticsearch instance
type ElasticsearchEventHandler struct {
	elasticInstance  string
	indexname        string
	eventChan        chan string
	eventFilter      map[string]interface{}
	waitgroup        sync.WaitGroup
	requestBodySlice []string
	requestBodyLock  sync.RWMutex
	requestLock      sync.Mutex
}

// Configure takes a viper configuration to set up this event handler
func (handler *ElasticsearchEventHandler) Configure(config *viper.Viper) error {
	utils.CreateDefaultEventElasticsearchConfig(config)
	handler.requestBodySlice = make([]string, 0)
	proto := "http"
	if config.GetBool("useTLS") {
		proto = "https"
	}
	handler.elasticInstance = fmt.Sprintf("%s://%s:%d", proto, config.GetString("server"), config.GetInt("port"))
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "Configure",
	}).Debugf("Instance is %s", handler.elasticInstance)
	handler.indexname = config.GetString("internal.indexname")
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "Configure",
	}).Debugf("Using index %s", handler.indexname)
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "Configure",
	}).Debugf("Event channel size is %d", config.GetInt("internal.channelsize"))
	handler.eventChan = make(chan string, config.GetInt("internal.channelsize"))
	handler.eventFilter = config.GetStringMap("filter")
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "Configure",
	}).Debug("Starting goroutines")
	go handler.prepareRequestBody()
	go handler.submitEvents(config.GetInt("internal.committimer"))
	return nil
}

// ProcessEvents takes a pointer to an array with events and passes them
// to the internal processing
func (handler *ElasticsearchEventHandler) ProcessEvents(events []*nraySchema.Event) {
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
func (handler *ElasticsearchEventHandler) ProcessEventStream(eventStream <-chan *nraySchema.Event) {
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "ProcessEventStream",
	}).Debug("Processing events")
	for event := range eventStream {
		serialized, err := protomarshaller.MarshalToString(event)
		utils.CheckError(err, false)
		handler.eventChan <- serialized
	}
}

// Close waits until the events are written and closes the file descriptor
func (handler *ElasticsearchEventHandler) Close() error {
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "Close",
	}).Debug("Closing EventHandler")
	handler.waitgroup.Wait()
	close(handler.eventChan)
	for len(handler.eventChan) > 0 { // Give time to flush events still in queue
		time.Sleep(1 * time.Second)
	}
	for {
		handler.requestBodyLock.RLock()
		if len(handler.requestBodySlice) > 0 {
			handler.requestBodyLock.RUnlock()
			time.Sleep(1 * time.Second)
		} else {
			handler.requestBodyLock.RUnlock()
			break
		}
	}
	time.Sleep(1 * time.Second)
	return nil
}

// Supposed to run as own goroutine.
func (handler *ElasticsearchEventHandler) prepareRequestBody() {
	metadata := fmt.Sprintf(elasticBulkActionAndMeta, handler.indexname)
	for {
		event, more := <-handler.eventChan
		if more {
			handler.requestBodyLock.Lock()
			if len(handler.eventFilter) > 0 {
				for filter, value := range handler.eventFilter {
					if FilterMatchesEvent(event, filter, value) {
						handler.requestBodySlice = append(handler.requestBodySlice, metadata)
						handler.requestBodySlice = append(handler.requestBodySlice, event)
						break
					}
				}
			} else {
				handler.requestBodySlice = append(handler.requestBodySlice, metadata)
				handler.requestBodySlice = append(handler.requestBodySlice, event)
			}
			handler.requestBodyLock.Unlock()
		} else {
			// Make sure there are no pending requests
			handler.requestLock.Lock()
			defer handler.requestLock.Unlock()
			return
		}
	}
}

type bulkResponse struct {
	Took   float64
	Errors bool
	Items  []interface{}
}

func (handler *ElasticsearchEventHandler) submitEvents(interval int) {
	log.WithFields(log.Fields{
		"module": "events.ElasticsearchEventHandler",
		"src":    "submitEvents",
	}).Debug("Submitting events")
	fmt.Println(interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	client := &http.Client{}
	for range ticker.C {
		handler.requestLock.Lock()
		handler.requestBodyLock.Lock()
		if len(handler.requestBodySlice) == 0 { // No data to submit
			handler.requestBodyLock.Unlock()
			handler.requestLock.Unlock()
			continue
		}
		requestBody := strings.Join(handler.requestBodySlice[:], "\n")
		requestBody = fmt.Sprintf("%s\n", requestBody)
		req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", handler.elasticInstance, "/_bulk"),
			bytes.NewBuffer([]byte(requestBody)))
		handler.requestBodySlice = make([]string, 0)
		handler.requestBodyLock.Unlock()
		req.Header.Set("Content-Type", "application/x-ndjson")
		resp, err := client.Do(req)
		utils.CheckError(err, false)
		body, _ := ioutil.ReadAll(resp.Body)
		parsedResponse := &bulkResponse{}
		json.Unmarshal(body, parsedResponse)
		if parsedResponse.Errors {
			for _, element := range parsedResponse.Items {
				e := element.(map[string]interface{})
				i := e["index"].(map[string]interface{})
				if i["error"] != nil {
					log.WithFields(log.Fields{
						"module": "events.ElasticsearchEventHandler",
						"src":    "submitEvents",
					}).Debug(spew.Sdump(element))
				}
			}
			// f, err := os.Create("errors.txt")
			// utils.CheckError(err, false)
			// _, err = f.WriteString(spew.Sdump(parsedResponse))
			// utils.CheckError(err, false)
			// f.Close()
			log.WithFields(log.Fields{
				"module": "events.ElasticsearchEventHandler",
				"src":    "submitEvents",
			}).Warning("Submission errors")
		}
		resp.Body.Close()
		handler.requestLock.Unlock()
	}
}
