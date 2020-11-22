package events

import (
	"github.com/golang/protobuf/jsonpb"
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/spf13/viper"
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
