// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.25.3
// source: storage/mitre.proto

package storage

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

type MitreTactic struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description   string                 `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MitreTactic) Reset() {
	*x = MitreTactic{}
	mi := &file_storage_mitre_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MitreTactic) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreTactic) ProtoMessage() {}

func (x *MitreTactic) ProtoReflect() protoreflect.Message {
	mi := &file_storage_mitre_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreTactic.ProtoReflect.Descriptor instead.
func (*MitreTactic) Descriptor() ([]byte, []int) {
	return file_storage_mitre_proto_rawDescGZIP(), []int{0}
}

func (x *MitreTactic) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *MitreTactic) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *MitreTactic) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

type MitreTechnique struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description   string                 `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MitreTechnique) Reset() {
	*x = MitreTechnique{}
	mi := &file_storage_mitre_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MitreTechnique) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreTechnique) ProtoMessage() {}

func (x *MitreTechnique) ProtoReflect() protoreflect.Message {
	mi := &file_storage_mitre_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreTechnique.ProtoReflect.Descriptor instead.
func (*MitreTechnique) Descriptor() ([]byte, []int) {
	return file_storage_mitre_proto_rawDescGZIP(), []int{1}
}

func (x *MitreTechnique) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *MitreTechnique) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *MitreTechnique) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

type MitreAttackVector struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Tactic        *MitreTactic           `protobuf:"bytes,1,opt,name=tactic,proto3" json:"tactic,omitempty"`
	Techniques    []*MitreTechnique      `protobuf:"bytes,2,rep,name=techniques,proto3" json:"techniques,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MitreAttackVector) Reset() {
	*x = MitreAttackVector{}
	mi := &file_storage_mitre_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MitreAttackVector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreAttackVector) ProtoMessage() {}

func (x *MitreAttackVector) ProtoReflect() protoreflect.Message {
	mi := &file_storage_mitre_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreAttackVector.ProtoReflect.Descriptor instead.
func (*MitreAttackVector) Descriptor() ([]byte, []int) {
	return file_storage_mitre_proto_rawDescGZIP(), []int{2}
}

func (x *MitreAttackVector) GetTactic() *MitreTactic {
	if x != nil {
		return x.Tactic
	}
	return nil
}

func (x *MitreAttackVector) GetTechniques() []*MitreTechnique {
	if x != nil {
		return x.Techniques
	}
	return nil
}

type MitreAttackMatrix struct {
	state         protoimpl.MessageState        `protogen:"open.v1"`
	MatrixInfo    *MitreAttackMatrix_MatrixInfo `protobuf:"bytes,1,opt,name=matrix_info,json=matrixInfo,proto3" json:"matrix_info,omitempty"`
	Vectors       []*MitreAttackVector          `protobuf:"bytes,2,rep,name=vectors,proto3" json:"vectors,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MitreAttackMatrix) Reset() {
	*x = MitreAttackMatrix{}
	mi := &file_storage_mitre_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MitreAttackMatrix) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreAttackMatrix) ProtoMessage() {}

func (x *MitreAttackMatrix) ProtoReflect() protoreflect.Message {
	mi := &file_storage_mitre_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreAttackMatrix.ProtoReflect.Descriptor instead.
func (*MitreAttackMatrix) Descriptor() ([]byte, []int) {
	return file_storage_mitre_proto_rawDescGZIP(), []int{3}
}

func (x *MitreAttackMatrix) GetMatrixInfo() *MitreAttackMatrix_MatrixInfo {
	if x != nil {
		return x.MatrixInfo
	}
	return nil
}

func (x *MitreAttackMatrix) GetVectors() []*MitreAttackVector {
	if x != nil {
		return x.Vectors
	}
	return nil
}

type MitreAttackBundle struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       string                 `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Matrices      []*MitreAttackMatrix   `protobuf:"bytes,2,rep,name=matrices,proto3" json:"matrices,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MitreAttackBundle) Reset() {
	*x = MitreAttackBundle{}
	mi := &file_storage_mitre_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MitreAttackBundle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreAttackBundle) ProtoMessage() {}

func (x *MitreAttackBundle) ProtoReflect() protoreflect.Message {
	mi := &file_storage_mitre_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreAttackBundle.ProtoReflect.Descriptor instead.
func (*MitreAttackBundle) Descriptor() ([]byte, []int) {
	return file_storage_mitre_proto_rawDescGZIP(), []int{4}
}

func (x *MitreAttackBundle) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *MitreAttackBundle) GetMatrices() []*MitreAttackMatrix {
	if x != nil {
		return x.Matrices
	}
	return nil
}

type MitreAttackMatrix_MatrixInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Domain        string                 `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	Platform      string                 `protobuf:"bytes,2,opt,name=platform,proto3" json:"platform,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MitreAttackMatrix_MatrixInfo) Reset() {
	*x = MitreAttackMatrix_MatrixInfo{}
	mi := &file_storage_mitre_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MitreAttackMatrix_MatrixInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreAttackMatrix_MatrixInfo) ProtoMessage() {}

func (x *MitreAttackMatrix_MatrixInfo) ProtoReflect() protoreflect.Message {
	mi := &file_storage_mitre_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreAttackMatrix_MatrixInfo.ProtoReflect.Descriptor instead.
func (*MitreAttackMatrix_MatrixInfo) Descriptor() ([]byte, []int) {
	return file_storage_mitre_proto_rawDescGZIP(), []int{3, 0}
}

func (x *MitreAttackMatrix_MatrixInfo) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *MitreAttackMatrix_MatrixInfo) GetPlatform() string {
	if x != nil {
		return x.Platform
	}
	return ""
}

var File_storage_mitre_proto protoreflect.FileDescriptor

const file_storage_mitre_proto_rawDesc = "" +
	"\n" +
	"\x13storage/mitre.proto\x12\astorage\"S\n" +
	"\vMitreTactic\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12\x12\n" +
	"\x04name\x18\x02 \x01(\tR\x04name\x12 \n" +
	"\vdescription\x18\x03 \x01(\tR\vdescription\"V\n" +
	"\x0eMitreTechnique\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12\x12\n" +
	"\x04name\x18\x02 \x01(\tR\x04name\x12 \n" +
	"\vdescription\x18\x03 \x01(\tR\vdescription\"z\n" +
	"\x11MitreAttackVector\x12,\n" +
	"\x06tactic\x18\x01 \x01(\v2\x14.storage.MitreTacticR\x06tactic\x127\n" +
	"\n" +
	"techniques\x18\x02 \x03(\v2\x17.storage.MitreTechniqueR\n" +
	"techniques\"\xd3\x01\n" +
	"\x11MitreAttackMatrix\x12F\n" +
	"\vmatrix_info\x18\x01 \x01(\v2%.storage.MitreAttackMatrix.MatrixInfoR\n" +
	"matrixInfo\x124\n" +
	"\avectors\x18\x02 \x03(\v2\x1a.storage.MitreAttackVectorR\avectors\x1a@\n" +
	"\n" +
	"MatrixInfo\x12\x16\n" +
	"\x06domain\x18\x01 \x01(\tR\x06domain\x12\x1a\n" +
	"\bplatform\x18\x02 \x01(\tR\bplatform\"e\n" +
	"\x11MitreAttackBundle\x12\x18\n" +
	"\aversion\x18\x01 \x01(\tR\aversion\x126\n" +
	"\bmatrices\x18\x02 \x03(\v2\x1a.storage.MitreAttackMatrixR\bmatricesB.\n" +
	"\x19io.stackrox.proto.storageZ\x11./storage;storageb\x06proto3"

var (
	file_storage_mitre_proto_rawDescOnce sync.Once
	file_storage_mitre_proto_rawDescData []byte
)

func file_storage_mitre_proto_rawDescGZIP() []byte {
	file_storage_mitre_proto_rawDescOnce.Do(func() {
		file_storage_mitre_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_storage_mitre_proto_rawDesc), len(file_storage_mitre_proto_rawDesc)))
	})
	return file_storage_mitre_proto_rawDescData
}

var file_storage_mitre_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_storage_mitre_proto_goTypes = []any{
	(*MitreTactic)(nil),                  // 0: storage.MitreTactic
	(*MitreTechnique)(nil),               // 1: storage.MitreTechnique
	(*MitreAttackVector)(nil),            // 2: storage.MitreAttackVector
	(*MitreAttackMatrix)(nil),            // 3: storage.MitreAttackMatrix
	(*MitreAttackBundle)(nil),            // 4: storage.MitreAttackBundle
	(*MitreAttackMatrix_MatrixInfo)(nil), // 5: storage.MitreAttackMatrix.MatrixInfo
}
var file_storage_mitre_proto_depIdxs = []int32{
	0, // 0: storage.MitreAttackVector.tactic:type_name -> storage.MitreTactic
	1, // 1: storage.MitreAttackVector.techniques:type_name -> storage.MitreTechnique
	5, // 2: storage.MitreAttackMatrix.matrix_info:type_name -> storage.MitreAttackMatrix.MatrixInfo
	2, // 3: storage.MitreAttackMatrix.vectors:type_name -> storage.MitreAttackVector
	3, // 4: storage.MitreAttackBundle.matrices:type_name -> storage.MitreAttackMatrix
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_storage_mitre_proto_init() }
func file_storage_mitre_proto_init() {
	if File_storage_mitre_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_storage_mitre_proto_rawDesc), len(file_storage_mitre_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_mitre_proto_goTypes,
		DependencyIndexes: file_storage_mitre_proto_depIdxs,
		MessageInfos:      file_storage_mitre_proto_msgTypes,
	}.Build()
	File_storage_mitre_proto = out.File
	file_storage_mitre_proto_goTypes = nil
	file_storage_mitre_proto_depIdxs = nil
}
