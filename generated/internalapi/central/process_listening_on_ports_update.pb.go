// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.25.3
// source: internalapi/central/process_listening_on_ports_update.proto

package central

import (
	storage "github.com/stackrox/rox/generated/storage"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ProcessListeningOnPortsUpdate struct {
	state                     protoimpl.MessageState                      `protogen:"open.v1"`
	ProcessesListeningOnPorts []*storage.ProcessListeningOnPortFromSensor `protobuf:"bytes,1,rep,name=processes_listening_on_ports,json=processesListeningOnPorts,proto3" json:"processes_listening_on_ports,omitempty"`
	Time                      *timestamppb.Timestamp                      `protobuf:"bytes,2,opt,name=time,proto3" json:"time,omitempty"`
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *ProcessListeningOnPortsUpdate) Reset() {
	*x = ProcessListeningOnPortsUpdate{}
	mi := &file_internalapi_central_process_listening_on_ports_update_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProcessListeningOnPortsUpdate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProcessListeningOnPortsUpdate) ProtoMessage() {}

func (x *ProcessListeningOnPortsUpdate) ProtoReflect() protoreflect.Message {
	mi := &file_internalapi_central_process_listening_on_ports_update_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProcessListeningOnPortsUpdate.ProtoReflect.Descriptor instead.
func (*ProcessListeningOnPortsUpdate) Descriptor() ([]byte, []int) {
	return file_internalapi_central_process_listening_on_ports_update_proto_rawDescGZIP(), []int{0}
}

func (x *ProcessListeningOnPortsUpdate) GetProcessesListeningOnPorts() []*storage.ProcessListeningOnPortFromSensor {
	if x != nil {
		return x.ProcessesListeningOnPorts
	}
	return nil
}

func (x *ProcessListeningOnPortsUpdate) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

var File_internalapi_central_process_listening_on_ports_update_proto protoreflect.FileDescriptor

const file_internalapi_central_process_listening_on_ports_update_proto_rawDesc = "" +
	"\n" +
	";internalapi/central/process_listening_on_ports_update.proto\x12\acentral\x1a\x1fgoogle/protobuf/timestamp.proto\x1a'storage/process_listening_on_port.proto\"\xbb\x01\n" +
	"\x1dProcessListeningOnPortsUpdate\x12j\n" +
	"\x1cprocesses_listening_on_ports\x18\x01 \x03(\v2).storage.ProcessListeningOnPortFromSensorR\x19processesListeningOnPorts\x12.\n" +
	"\x04time\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\x04timeB\x1fZ\x1d./internalapi/central;centralb\x06proto3"

var (
	file_internalapi_central_process_listening_on_ports_update_proto_rawDescOnce sync.Once
	file_internalapi_central_process_listening_on_ports_update_proto_rawDescData []byte
)

func file_internalapi_central_process_listening_on_ports_update_proto_rawDescGZIP() []byte {
	file_internalapi_central_process_listening_on_ports_update_proto_rawDescOnce.Do(func() {
		file_internalapi_central_process_listening_on_ports_update_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_internalapi_central_process_listening_on_ports_update_proto_rawDesc), len(file_internalapi_central_process_listening_on_ports_update_proto_rawDesc)))
	})
	return file_internalapi_central_process_listening_on_ports_update_proto_rawDescData
}

var file_internalapi_central_process_listening_on_ports_update_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_internalapi_central_process_listening_on_ports_update_proto_goTypes = []any{
	(*ProcessListeningOnPortsUpdate)(nil),            // 0: central.ProcessListeningOnPortsUpdate
	(*storage.ProcessListeningOnPortFromSensor)(nil), // 1: storage.ProcessListeningOnPortFromSensor
	(*timestamppb.Timestamp)(nil),                    // 2: google.protobuf.Timestamp
}
var file_internalapi_central_process_listening_on_ports_update_proto_depIdxs = []int32{
	1, // 0: central.ProcessListeningOnPortsUpdate.processes_listening_on_ports:type_name -> storage.ProcessListeningOnPortFromSensor
	2, // 1: central.ProcessListeningOnPortsUpdate.time:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_internalapi_central_process_listening_on_ports_update_proto_init() }
func file_internalapi_central_process_listening_on_ports_update_proto_init() {
	if File_internalapi_central_process_listening_on_ports_update_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_internalapi_central_process_listening_on_ports_update_proto_rawDesc), len(file_internalapi_central_process_listening_on_ports_update_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_internalapi_central_process_listening_on_ports_update_proto_goTypes,
		DependencyIndexes: file_internalapi_central_process_listening_on_ports_update_proto_depIdxs,
		MessageInfos:      file_internalapi_central_process_listening_on_ports_update_proto_msgTypes,
	}.Build()
	File_internalapi_central_process_listening_on_ports_update_proto = out.File
	file_internalapi_central_process_listening_on_ports_update_proto_goTypes = nil
	file_internalapi_central_process_listening_on_ports_update_proto_depIdxs = nil
}
