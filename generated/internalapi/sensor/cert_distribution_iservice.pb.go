// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.25.3
// source: internalapi/sensor/cert_distribution_iservice.proto

package sensor

import (
	storage "github.com/stackrox/rox/generated/storage"
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

type FetchCertificateRequest struct {
	state               protoimpl.MessageState `protogen:"open.v1"`
	ServiceType         storage.ServiceType    `protobuf:"varint,1,opt,name=service_type,json=serviceType,proto3,enum=storage.ServiceType" json:"service_type,omitempty"`
	ServiceAccountToken string                 `protobuf:"bytes,2,opt,name=service_account_token,json=serviceAccountToken,proto3" json:"service_account_token,omitempty"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

func (x *FetchCertificateRequest) Reset() {
	*x = FetchCertificateRequest{}
	mi := &file_internalapi_sensor_cert_distribution_iservice_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FetchCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FetchCertificateRequest) ProtoMessage() {}

func (x *FetchCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internalapi_sensor_cert_distribution_iservice_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FetchCertificateRequest.ProtoReflect.Descriptor instead.
func (*FetchCertificateRequest) Descriptor() ([]byte, []int) {
	return file_internalapi_sensor_cert_distribution_iservice_proto_rawDescGZIP(), []int{0}
}

func (x *FetchCertificateRequest) GetServiceType() storage.ServiceType {
	if x != nil {
		return x.ServiceType
	}
	return storage.ServiceType(0)
}

func (x *FetchCertificateRequest) GetServiceAccountToken() string {
	if x != nil {
		return x.ServiceAccountToken
	}
	return ""
}

type FetchCertificateResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PemCert       string                 `protobuf:"bytes,1,opt,name=pem_cert,json=pemCert,proto3" json:"pem_cert,omitempty"`
	PemKey        string                 `protobuf:"bytes,2,opt,name=pem_key,json=pemKey,proto3" json:"pem_key,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FetchCertificateResponse) Reset() {
	*x = FetchCertificateResponse{}
	mi := &file_internalapi_sensor_cert_distribution_iservice_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FetchCertificateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FetchCertificateResponse) ProtoMessage() {}

func (x *FetchCertificateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internalapi_sensor_cert_distribution_iservice_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FetchCertificateResponse.ProtoReflect.Descriptor instead.
func (*FetchCertificateResponse) Descriptor() ([]byte, []int) {
	return file_internalapi_sensor_cert_distribution_iservice_proto_rawDescGZIP(), []int{1}
}

func (x *FetchCertificateResponse) GetPemCert() string {
	if x != nil {
		return x.PemCert
	}
	return ""
}

func (x *FetchCertificateResponse) GetPemKey() string {
	if x != nil {
		return x.PemKey
	}
	return ""
}

var File_internalapi_sensor_cert_distribution_iservice_proto protoreflect.FileDescriptor

const file_internalapi_sensor_cert_distribution_iservice_proto_rawDesc = "" +
	"\n" +
	"3internalapi/sensor/cert_distribution_iservice.proto\x12\x06sensor\x1a\x1estorage/service_identity.proto\"\x86\x01\n" +
	"\x17FetchCertificateRequest\x127\n" +
	"\fservice_type\x18\x01 \x01(\x0e2\x14.storage.ServiceTypeR\vserviceType\x122\n" +
	"\x15service_account_token\x18\x02 \x01(\tR\x13serviceAccountToken\"N\n" +
	"\x18FetchCertificateResponse\x12\x19\n" +
	"\bpem_cert\x18\x01 \x01(\tR\apemCert\x12\x17\n" +
	"\apem_key\x18\x02 \x01(\tR\x06pemKey2p\n" +
	"\x17CertDistributionService\x12U\n" +
	"\x10FetchCertificate\x12\x1f.sensor.FetchCertificateRequest\x1a .sensor.FetchCertificateResponseB\x1dZ\x1b./internalapi/sensor;sensorb\x06proto3"

var (
	file_internalapi_sensor_cert_distribution_iservice_proto_rawDescOnce sync.Once
	file_internalapi_sensor_cert_distribution_iservice_proto_rawDescData []byte
)

func file_internalapi_sensor_cert_distribution_iservice_proto_rawDescGZIP() []byte {
	file_internalapi_sensor_cert_distribution_iservice_proto_rawDescOnce.Do(func() {
		file_internalapi_sensor_cert_distribution_iservice_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_internalapi_sensor_cert_distribution_iservice_proto_rawDesc), len(file_internalapi_sensor_cert_distribution_iservice_proto_rawDesc)))
	})
	return file_internalapi_sensor_cert_distribution_iservice_proto_rawDescData
}

var file_internalapi_sensor_cert_distribution_iservice_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_internalapi_sensor_cert_distribution_iservice_proto_goTypes = []any{
	(*FetchCertificateRequest)(nil),  // 0: sensor.FetchCertificateRequest
	(*FetchCertificateResponse)(nil), // 1: sensor.FetchCertificateResponse
	(storage.ServiceType)(0),         // 2: storage.ServiceType
}
var file_internalapi_sensor_cert_distribution_iservice_proto_depIdxs = []int32{
	2, // 0: sensor.FetchCertificateRequest.service_type:type_name -> storage.ServiceType
	0, // 1: sensor.CertDistributionService.FetchCertificate:input_type -> sensor.FetchCertificateRequest
	1, // 2: sensor.CertDistributionService.FetchCertificate:output_type -> sensor.FetchCertificateResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_internalapi_sensor_cert_distribution_iservice_proto_init() }
func file_internalapi_sensor_cert_distribution_iservice_proto_init() {
	if File_internalapi_sensor_cert_distribution_iservice_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_internalapi_sensor_cert_distribution_iservice_proto_rawDesc), len(file_internalapi_sensor_cert_distribution_iservice_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_internalapi_sensor_cert_distribution_iservice_proto_goTypes,
		DependencyIndexes: file_internalapi_sensor_cert_distribution_iservice_proto_depIdxs,
		MessageInfos:      file_internalapi_sensor_cert_distribution_iservice_proto_msgTypes,
	}.Build()
	File_internalapi_sensor_cert_distribution_iservice_proto = out.File
	file_internalapi_sensor_cert_distribution_iservice_proto_goTypes = nil
	file_internalapi_sensor_cert_distribution_iservice_proto_depIdxs = nil
}
