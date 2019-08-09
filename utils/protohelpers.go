package utils

import (
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
)

// JSONtoProtoValue converts any json to a protobuf value
func JSONtoProtoValue(json []byte) (*structpb.Value, error) {
	result := &structpb.Value{}
	if err := jsonpb.UnmarshalString(string(json), result); err != nil {
		return nil, err
	}
	return result, nil
}
