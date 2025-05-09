// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.25.3
// source: storage/log.proto

package storage

import (
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

type LogImbue struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" sql:"pk"`               // @gotags: sql:"pk"
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty" search:"Log Imbue Creation Time,hidden"` // @gotags: search:"Log Imbue Creation Time,hidden"
	Log           []byte                 `protobuf:"bytes,3,opt,name=log,proto3" json:"log,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogImbue) Reset() {
	*x = LogImbue{}
	mi := &file_storage_log_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogImbue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogImbue) ProtoMessage() {}

func (x *LogImbue) ProtoReflect() protoreflect.Message {
	mi := &file_storage_log_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogImbue.ProtoReflect.Descriptor instead.
func (*LogImbue) Descriptor() ([]byte, []int) {
	return file_storage_log_proto_rawDescGZIP(), []int{0}
}

func (x *LogImbue) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *LogImbue) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *LogImbue) GetLog() []byte {
	if x != nil {
		return x.Log
	}
	return nil
}

var File_storage_log_proto protoreflect.FileDescriptor

const file_storage_log_proto_rawDesc = "" +
	"\n" +
	"\x11storage/log.proto\x12\astorage\x1a\x1fgoogle/protobuf/timestamp.proto\"f\n" +
	"\bLogImbue\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x128\n" +
	"\ttimestamp\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\x12\x10\n" +
	"\x03log\x18\x03 \x01(\fR\x03logB.\n" +
	"\x19io.stackrox.proto.storageZ\x11./storage;storageb\x06proto3"

var (
	file_storage_log_proto_rawDescOnce sync.Once
	file_storage_log_proto_rawDescData []byte
)

func file_storage_log_proto_rawDescGZIP() []byte {
	file_storage_log_proto_rawDescOnce.Do(func() {
		file_storage_log_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_storage_log_proto_rawDesc), len(file_storage_log_proto_rawDesc)))
	})
	return file_storage_log_proto_rawDescData
}

var file_storage_log_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_storage_log_proto_goTypes = []any{
	(*LogImbue)(nil),              // 0: storage.LogImbue
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_storage_log_proto_depIdxs = []int32{
	1, // 0: storage.LogImbue.timestamp:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_storage_log_proto_init() }
func file_storage_log_proto_init() {
	if File_storage_log_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_storage_log_proto_rawDesc), len(file_storage_log_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_log_proto_goTypes,
		DependencyIndexes: file_storage_log_proto_depIdxs,
		MessageInfos:      file_storage_log_proto_msgTypes,
	}.Build()
	File_storage_log_proto = out.File
	file_storage_log_proto_goTypes = nil
	file_storage_log_proto_depIdxs = nil
}
