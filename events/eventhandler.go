package events

import (
	"fmt"

	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/golang/protobuf/jsonpb"
	"github.com/spf13/viper"
	"github.com/thedevsaddam/gojsonq"
)

// RegisteredHandlers contains all handlers that may be configured by a user
var RegisteredHandlers = []string{"json-file", "terminal", "elasticsearch"}

var protomarshaller = jsonpb.Marshaler{
	EnumsAsInts:  false,
	EmitDefaults: true,
	Indent:       "",
	OrigName:     true,
	AnyResolver:  nil,
}

// GetEventHandler returns the correct event handler for a event handler name
func GetEventHandler(EventHandlerName string) EventHandler {
	switch EventHandlerName {
	case "json-file":
		return &JSONFileEventHandler{}
	case "terminal":
		return &TerminalEventHandler{}
	case "elasticsearch":
		return &ElasticsearchEventHandler{}
	default:
		return nil
	}
}

// EventHandler is the interface each type of handling events has to implement
type EventHandler interface {
	Configure(*viper.Viper) error
	ProcessEvents([]*nraySchema.Event)
	ProcessEventStream(<-chan *nraySchema.Event)
	Close() error
}

// FilterMatchesEvent returns true if the event has the filter string and its value matches the provided value
func FilterMatchesEvent(event string, filter string, value interface{}) bool {
	if value == nil {
		return gojsonq.New().JSONString(event).Find(filter) != nil
	}
	return fmt.Sprintf("%#v", gojsonq.New().JSONString(event).Find(filter)) == fmt.Sprintf("%#v", value)

}
