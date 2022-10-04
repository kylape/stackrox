// Code generated by pg-bindings generator. DO NOT EDIT.
package schema

import (
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres/schema"
)

// ConvertTestChild1FromProto converts a `*storage.TestChild1` to Gorm model
func ConvertTestChild1FromProto(obj *storage.TestChild1) (*schema.TestChild1, error) {
	serialized, err := obj.Marshal()
	if err != nil {
		return nil, err
	}
	model := &schema.TestChild1{
		Id:         obj.GetId(),
		Val:        obj.GetVal(),
		Serialized: serialized,
	}
	return model, nil
}

// ConvertTestChild1ToProto converts Gorm model `TestChild1` to its protobuf type object
func ConvertTestChild1ToProto(m *schema.TestChild1) (*storage.TestChild1, error) {
	var msg storage.TestChild1
	if err := msg.Unmarshal(m.Serialized); err != nil {
		return nil, err
	}
	return &msg, nil
}