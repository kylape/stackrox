// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v4.25.3
// source: api/v1/administration_events_service.proto

package v1

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

// AdministrationEventType exposes the different types of events.
type AdministrationEventType int32

const (
	AdministrationEventType_ADMINISTRATION_EVENT_TYPE_UNKNOWN     AdministrationEventType = 0
	AdministrationEventType_ADMINISTRATION_EVENT_TYPE_GENERIC     AdministrationEventType = 1
	AdministrationEventType_ADMINISTRATION_EVENT_TYPE_LOG_MESSAGE AdministrationEventType = 2
)

// Enum value maps for AdministrationEventType.
var (
	AdministrationEventType_name = map[int32]string{
		0: "ADMINISTRATION_EVENT_TYPE_UNKNOWN",
		1: "ADMINISTRATION_EVENT_TYPE_GENERIC",
		2: "ADMINISTRATION_EVENT_TYPE_LOG_MESSAGE",
	}
	AdministrationEventType_value = map[string]int32{
		"ADMINISTRATION_EVENT_TYPE_UNKNOWN":     0,
		"ADMINISTRATION_EVENT_TYPE_GENERIC":     1,
		"ADMINISTRATION_EVENT_TYPE_LOG_MESSAGE": 2,
	}
)

func (x AdministrationEventType) Enum() *AdministrationEventType {
	p := new(AdministrationEventType)
	*p = x
	return p
}

func (x AdministrationEventType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AdministrationEventType) Descriptor() protoreflect.EnumDescriptor {
	return file_api_v1_administration_events_service_proto_enumTypes[0].Descriptor()
}

func (AdministrationEventType) Type() protoreflect.EnumType {
	return &file_api_v1_administration_events_service_proto_enumTypes[0]
}

func (x AdministrationEventType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AdministrationEventType.Descriptor instead.
func (AdministrationEventType) EnumDescriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{0}
}

// AdministrationEventLevel exposes the different levels of events.
type AdministrationEventLevel int32

const (
	AdministrationEventLevel_ADMINISTRATION_EVENT_LEVEL_UNKNOWN AdministrationEventLevel = 0
	AdministrationEventLevel_ADMINISTRATION_EVENT_LEVEL_INFO    AdministrationEventLevel = 1
	AdministrationEventLevel_ADMINISTRATION_EVENT_LEVEL_SUCCESS AdministrationEventLevel = 2
	AdministrationEventLevel_ADMINISTRATION_EVENT_LEVEL_WARNING AdministrationEventLevel = 3
	AdministrationEventLevel_ADMINISTRATION_EVENT_LEVEL_ERROR   AdministrationEventLevel = 4
)

// Enum value maps for AdministrationEventLevel.
var (
	AdministrationEventLevel_name = map[int32]string{
		0: "ADMINISTRATION_EVENT_LEVEL_UNKNOWN",
		1: "ADMINISTRATION_EVENT_LEVEL_INFO",
		2: "ADMINISTRATION_EVENT_LEVEL_SUCCESS",
		3: "ADMINISTRATION_EVENT_LEVEL_WARNING",
		4: "ADMINISTRATION_EVENT_LEVEL_ERROR",
	}
	AdministrationEventLevel_value = map[string]int32{
		"ADMINISTRATION_EVENT_LEVEL_UNKNOWN": 0,
		"ADMINISTRATION_EVENT_LEVEL_INFO":    1,
		"ADMINISTRATION_EVENT_LEVEL_SUCCESS": 2,
		"ADMINISTRATION_EVENT_LEVEL_WARNING": 3,
		"ADMINISTRATION_EVENT_LEVEL_ERROR":   4,
	}
)

func (x AdministrationEventLevel) Enum() *AdministrationEventLevel {
	p := new(AdministrationEventLevel)
	*p = x
	return p
}

func (x AdministrationEventLevel) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AdministrationEventLevel) Descriptor() protoreflect.EnumDescriptor {
	return file_api_v1_administration_events_service_proto_enumTypes[1].Descriptor()
}

func (AdministrationEventLevel) Type() protoreflect.EnumType {
	return &file_api_v1_administration_events_service_proto_enumTypes[1]
}

func (x AdministrationEventLevel) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AdministrationEventLevel.Descriptor instead.
func (AdministrationEventLevel) EnumDescriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{1}
}

// AdministrationEvents are administrative events emitted by Central. They are used to create
// transparency for users for asynchronous, background tasks. Events are part of Central's
// system health view.
type AdministrationEvent struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// UUID of the event.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Type of the event.
	Type AdministrationEventType `protobuf:"varint,2,opt,name=type,proto3,enum=v1.AdministrationEventType" json:"type,omitempty"`
	// Level associated with the event. The level is categorized into danger, warn, info,
	// success.
	Level AdministrationEventLevel `protobuf:"varint,3,opt,name=level,proto3,enum=v1.AdministrationEventLevel" json:"level,omitempty"`
	// Message associated with the event. The message may include detailed information
	// for this particular event.
	Message string `protobuf:"bytes,4,opt,name=message,proto3" json:"message,omitempty"`
	// Hint associated with the event. The hint may include different information based
	// on the type of event. It can include instructions to resolve an event, or
	// informational hints.
	Hint string `protobuf:"bytes,5,opt,name=hint,proto3" json:"hint,omitempty"`
	// Domain associated with the event. An event's domain outlines the feature domain where
	// the event was created from. As an example, this might be "Image Scanning".
	// In case of events that cannot be tied to a specific domain, this will be "General".
	Domain   string                        `protobuf:"bytes,6,opt,name=domain,proto3" json:"domain,omitempty"`
	Resource *AdministrationEvent_Resource `protobuf:"bytes,7,opt,name=resource,proto3" json:"resource,omitempty"`
	// Occurrences associated with the event. When events may occur multiple times, the
	// occurrences track the amount.
	NumOccurrences int64 `protobuf:"varint,8,opt,name=num_occurrences,json=numOccurrences,proto3" json:"num_occurrences,omitempty"`
	// Specifies the time when the event has last occurred.
	LastOccurredAt *timestamppb.Timestamp `protobuf:"bytes,9,opt,name=last_occurred_at,json=lastOccurredAt,proto3" json:"last_occurred_at,omitempty"`
	// Specifies the time when the event has been created.
	CreatedAt     *timestamppb.Timestamp `protobuf:"bytes,10,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdministrationEvent) Reset() {
	*x = AdministrationEvent{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdministrationEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdministrationEvent) ProtoMessage() {}

func (x *AdministrationEvent) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdministrationEvent.ProtoReflect.Descriptor instead.
func (*AdministrationEvent) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{0}
}

func (x *AdministrationEvent) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *AdministrationEvent) GetType() AdministrationEventType {
	if x != nil {
		return x.Type
	}
	return AdministrationEventType_ADMINISTRATION_EVENT_TYPE_UNKNOWN
}

func (x *AdministrationEvent) GetLevel() AdministrationEventLevel {
	if x != nil {
		return x.Level
	}
	return AdministrationEventLevel_ADMINISTRATION_EVENT_LEVEL_UNKNOWN
}

func (x *AdministrationEvent) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *AdministrationEvent) GetHint() string {
	if x != nil {
		return x.Hint
	}
	return ""
}

func (x *AdministrationEvent) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *AdministrationEvent) GetResource() *AdministrationEvent_Resource {
	if x != nil {
		return x.Resource
	}
	return nil
}

func (x *AdministrationEvent) GetNumOccurrences() int64 {
	if x != nil {
		return x.NumOccurrences
	}
	return 0
}

func (x *AdministrationEvent) GetLastOccurredAt() *timestamppb.Timestamp {
	if x != nil {
		return x.LastOccurredAt
	}
	return nil
}

func (x *AdministrationEvent) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

type AdministrationEventsFilter struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Matches events with last_occurred_at after a specific timestamp, i.e. the lower boundary.
	From *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	// Matches events with last_occurred_at before a specific timestamp, i.e. the upper boundary.
	Until *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=until,proto3" json:"until,omitempty"`
	// Matches events from a specific domain.
	Domain []string `protobuf:"bytes,3,rep,name=domain,proto3" json:"domain,omitempty"`
	// Matches events associated with a specific resource type.
	ResourceType []string `protobuf:"bytes,4,rep,name=resource_type,json=resourceType,proto3" json:"resource_type,omitempty"`
	// Matches events based on their type.
	Type []AdministrationEventType `protobuf:"varint,5,rep,packed,name=type,proto3,enum=v1.AdministrationEventType" json:"type,omitempty"`
	// Matches events based on their level.
	Level         []AdministrationEventLevel `protobuf:"varint,6,rep,packed,name=level,proto3,enum=v1.AdministrationEventLevel" json:"level,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdministrationEventsFilter) Reset() {
	*x = AdministrationEventsFilter{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdministrationEventsFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdministrationEventsFilter) ProtoMessage() {}

func (x *AdministrationEventsFilter) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdministrationEventsFilter.ProtoReflect.Descriptor instead.
func (*AdministrationEventsFilter) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{1}
}

func (x *AdministrationEventsFilter) GetFrom() *timestamppb.Timestamp {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *AdministrationEventsFilter) GetUntil() *timestamppb.Timestamp {
	if x != nil {
		return x.Until
	}
	return nil
}

func (x *AdministrationEventsFilter) GetDomain() []string {
	if x != nil {
		return x.Domain
	}
	return nil
}

func (x *AdministrationEventsFilter) GetResourceType() []string {
	if x != nil {
		return x.ResourceType
	}
	return nil
}

func (x *AdministrationEventsFilter) GetType() []AdministrationEventType {
	if x != nil {
		return x.Type
	}
	return nil
}

func (x *AdministrationEventsFilter) GetLevel() []AdministrationEventLevel {
	if x != nil {
		return x.Level
	}
	return nil
}

type CountAdministrationEventsRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// For filtering the events based on the requested fields.
	Filter        *AdministrationEventsFilter `protobuf:"bytes,1,opt,name=filter,proto3" json:"filter,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CountAdministrationEventsRequest) Reset() {
	*x = CountAdministrationEventsRequest{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CountAdministrationEventsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CountAdministrationEventsRequest) ProtoMessage() {}

func (x *CountAdministrationEventsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CountAdministrationEventsRequest.ProtoReflect.Descriptor instead.
func (*CountAdministrationEventsRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{2}
}

func (x *CountAdministrationEventsRequest) GetFilter() *AdministrationEventsFilter {
	if x != nil {
		return x.Filter
	}
	return nil
}

type CountAdministrationEventsResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The total number of events after filtering and deduplication.
	Count         int32 `protobuf:"varint,1,opt,name=count,proto3" json:"count,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CountAdministrationEventsResponse) Reset() {
	*x = CountAdministrationEventsResponse{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CountAdministrationEventsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CountAdministrationEventsResponse) ProtoMessage() {}

func (x *CountAdministrationEventsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CountAdministrationEventsResponse.ProtoReflect.Descriptor instead.
func (*CountAdministrationEventsResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{3}
}

func (x *CountAdministrationEventsResponse) GetCount() int32 {
	if x != nil {
		return x.Count
	}
	return 0
}

type GetAdministrationEventResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Event         *AdministrationEvent   `protobuf:"bytes,1,opt,name=event,proto3" json:"event,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetAdministrationEventResponse) Reset() {
	*x = GetAdministrationEventResponse{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetAdministrationEventResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAdministrationEventResponse) ProtoMessage() {}

func (x *GetAdministrationEventResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAdministrationEventResponse.ProtoReflect.Descriptor instead.
func (*GetAdministrationEventResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{4}
}

func (x *GetAdministrationEventResponse) GetEvent() *AdministrationEvent {
	if x != nil {
		return x.Event
	}
	return nil
}

type ListAdministrationEventsRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// For dividing the events response into chunks.
	Pagination *Pagination `protobuf:"bytes,1,opt,name=pagination,proto3" json:"pagination,omitempty"`
	// For filtering the events based on the requested fields.
	Filter        *AdministrationEventsFilter `protobuf:"bytes,2,opt,name=filter,proto3" json:"filter,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListAdministrationEventsRequest) Reset() {
	*x = ListAdministrationEventsRequest{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListAdministrationEventsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListAdministrationEventsRequest) ProtoMessage() {}

func (x *ListAdministrationEventsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListAdministrationEventsRequest.ProtoReflect.Descriptor instead.
func (*ListAdministrationEventsRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{5}
}

func (x *ListAdministrationEventsRequest) GetPagination() *Pagination {
	if x != nil {
		return x.Pagination
	}
	return nil
}

func (x *ListAdministrationEventsRequest) GetFilter() *AdministrationEventsFilter {
	if x != nil {
		return x.Filter
	}
	return nil
}

type ListAdministrationEventsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Events        []*AdministrationEvent `protobuf:"bytes,1,rep,name=events,proto3" json:"events,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListAdministrationEventsResponse) Reset() {
	*x = ListAdministrationEventsResponse{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListAdministrationEventsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListAdministrationEventsResponse) ProtoMessage() {}

func (x *ListAdministrationEventsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListAdministrationEventsResponse.ProtoReflect.Descriptor instead.
func (*ListAdministrationEventsResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{6}
}

func (x *ListAdministrationEventsResponse) GetEvents() []*AdministrationEvent {
	if x != nil {
		return x.Events
	}
	return nil
}

// Resource holds all information about the resource associated with the event.
type AdministrationEvent_Resource struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Resource type associated with the event. An event may refer to an underlying resource
	// such as a particular image. In that case, the resource type will be filled here.
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// Resource ID associated with the event. If an event refers to an underlying resource,
	// the resource ID identifies the underlying resource. The resource ID is not guaranteed
	// to be set, depending on the context of the administration event.
	Id string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// Resource name associated with the event. If an event refers to an underlying resource,
	// the resource name identifies the underlying resource. The resource name is not guaranteed
	// to be set, depending on the context of the administration event.
	Name          string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdministrationEvent_Resource) Reset() {
	*x = AdministrationEvent_Resource{}
	mi := &file_api_v1_administration_events_service_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdministrationEvent_Resource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdministrationEvent_Resource) ProtoMessage() {}

func (x *AdministrationEvent_Resource) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_administration_events_service_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdministrationEvent_Resource.ProtoReflect.Descriptor instead.
func (*AdministrationEvent_Resource) Descriptor() ([]byte, []int) {
	return file_api_v1_administration_events_service_proto_rawDescGZIP(), []int{0, 0}
}

func (x *AdministrationEvent_Resource) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *AdministrationEvent_Resource) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *AdministrationEvent_Resource) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_api_v1_administration_events_service_proto protoreflect.FileDescriptor

const file_api_v1_administration_events_service_proto_rawDesc = "" +
	"\n" +
	"*api/v1/administration_events_service.proto\x12\x02v1\x1a\x13api/v1/common.proto\x1a\x17api/v1/pagination.proto\x1a\x1cgoogle/api/annotations.proto\x1a\x1fgoogle/protobuf/timestamp.proto\"\xfc\x03\n" +
	"\x13AdministrationEvent\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12/\n" +
	"\x04type\x18\x02 \x01(\x0e2\x1b.v1.AdministrationEventTypeR\x04type\x122\n" +
	"\x05level\x18\x03 \x01(\x0e2\x1c.v1.AdministrationEventLevelR\x05level\x12\x18\n" +
	"\amessage\x18\x04 \x01(\tR\amessage\x12\x12\n" +
	"\x04hint\x18\x05 \x01(\tR\x04hint\x12\x16\n" +
	"\x06domain\x18\x06 \x01(\tR\x06domain\x12<\n" +
	"\bresource\x18\a \x01(\v2 .v1.AdministrationEvent.ResourceR\bresource\x12'\n" +
	"\x0fnum_occurrences\x18\b \x01(\x03R\x0enumOccurrences\x12D\n" +
	"\x10last_occurred_at\x18\t \x01(\v2\x1a.google.protobuf.TimestampR\x0elastOccurredAt\x129\n" +
	"\n" +
	"created_at\x18\n" +
	" \x01(\v2\x1a.google.protobuf.TimestampR\tcreatedAt\x1aB\n" +
	"\bResource\x12\x12\n" +
	"\x04type\x18\x01 \x01(\tR\x04type\x12\x0e\n" +
	"\x02id\x18\x02 \x01(\tR\x02id\x12\x12\n" +
	"\x04name\x18\x03 \x01(\tR\x04name\"\xa0\x02\n" +
	"\x1aAdministrationEventsFilter\x12.\n" +
	"\x04from\x18\x01 \x01(\v2\x1a.google.protobuf.TimestampR\x04from\x120\n" +
	"\x05until\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\x05until\x12\x16\n" +
	"\x06domain\x18\x03 \x03(\tR\x06domain\x12#\n" +
	"\rresource_type\x18\x04 \x03(\tR\fresourceType\x12/\n" +
	"\x04type\x18\x05 \x03(\x0e2\x1b.v1.AdministrationEventTypeR\x04type\x122\n" +
	"\x05level\x18\x06 \x03(\x0e2\x1c.v1.AdministrationEventLevelR\x05level\"Z\n" +
	" CountAdministrationEventsRequest\x126\n" +
	"\x06filter\x18\x01 \x01(\v2\x1e.v1.AdministrationEventsFilterR\x06filter\"9\n" +
	"!CountAdministrationEventsResponse\x12\x14\n" +
	"\x05count\x18\x01 \x01(\x05R\x05count\"O\n" +
	"\x1eGetAdministrationEventResponse\x12-\n" +
	"\x05event\x18\x01 \x01(\v2\x17.v1.AdministrationEventR\x05event\"\x89\x01\n" +
	"\x1fListAdministrationEventsRequest\x12.\n" +
	"\n" +
	"pagination\x18\x01 \x01(\v2\x0e.v1.PaginationR\n" +
	"pagination\x126\n" +
	"\x06filter\x18\x02 \x01(\v2\x1e.v1.AdministrationEventsFilterR\x06filter\"S\n" +
	" ListAdministrationEventsResponse\x12/\n" +
	"\x06events\x18\x01 \x03(\v2\x17.v1.AdministrationEventR\x06events*\x92\x01\n" +
	"\x17AdministrationEventType\x12%\n" +
	"!ADMINISTRATION_EVENT_TYPE_UNKNOWN\x10\x00\x12%\n" +
	"!ADMINISTRATION_EVENT_TYPE_GENERIC\x10\x01\x12)\n" +
	"%ADMINISTRATION_EVENT_TYPE_LOG_MESSAGE\x10\x02*\xdd\x01\n" +
	"\x18AdministrationEventLevel\x12&\n" +
	"\"ADMINISTRATION_EVENT_LEVEL_UNKNOWN\x10\x00\x12#\n" +
	"\x1fADMINISTRATION_EVENT_LEVEL_INFO\x10\x01\x12&\n" +
	"\"ADMINISTRATION_EVENT_LEVEL_SUCCESS\x10\x02\x12&\n" +
	"\"ADMINISTRATION_EVENT_LEVEL_WARNING\x10\x03\x12$\n" +
	" ADMINISTRATION_EVENT_LEVEL_ERROR\x10\x042\xb3\x03\n" +
	"\x1aAdministrationEventService\x12\x91\x01\n" +
	"\x19CountAdministrationEvents\x12$.v1.CountAdministrationEventsRequest\x1a%.v1.CountAdministrationEventsResponse\"'\x82\xd3\xe4\x93\x02!\x12\x1f/v1/count/administration/events\x12v\n" +
	"\x16GetAdministrationEvent\x12\x10.v1.ResourceByID\x1a\".v1.GetAdministrationEventResponse\"&\x82\xd3\xe4\x93\x02 \x12\x1e/v1/administration/events/{id}\x12\x88\x01\n" +
	"\x18ListAdministrationEvents\x12#.v1.ListAdministrationEventsRequest\x1a$.v1.ListAdministrationEventsResponse\"!\x82\xd3\xe4\x93\x02\x1b\x12\x19/v1/administration/eventsB'\n" +
	"\x18io.stackrox.proto.api.v1Z\v./api/v1;v1X\x02b\x06proto3"

var (
	file_api_v1_administration_events_service_proto_rawDescOnce sync.Once
	file_api_v1_administration_events_service_proto_rawDescData []byte
)

func file_api_v1_administration_events_service_proto_rawDescGZIP() []byte {
	file_api_v1_administration_events_service_proto_rawDescOnce.Do(func() {
		file_api_v1_administration_events_service_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_api_v1_administration_events_service_proto_rawDesc), len(file_api_v1_administration_events_service_proto_rawDesc)))
	})
	return file_api_v1_administration_events_service_proto_rawDescData
}

var file_api_v1_administration_events_service_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_api_v1_administration_events_service_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_api_v1_administration_events_service_proto_goTypes = []any{
	(AdministrationEventType)(0),              // 0: v1.AdministrationEventType
	(AdministrationEventLevel)(0),             // 1: v1.AdministrationEventLevel
	(*AdministrationEvent)(nil),               // 2: v1.AdministrationEvent
	(*AdministrationEventsFilter)(nil),        // 3: v1.AdministrationEventsFilter
	(*CountAdministrationEventsRequest)(nil),  // 4: v1.CountAdministrationEventsRequest
	(*CountAdministrationEventsResponse)(nil), // 5: v1.CountAdministrationEventsResponse
	(*GetAdministrationEventResponse)(nil),    // 6: v1.GetAdministrationEventResponse
	(*ListAdministrationEventsRequest)(nil),   // 7: v1.ListAdministrationEventsRequest
	(*ListAdministrationEventsResponse)(nil),  // 8: v1.ListAdministrationEventsResponse
	(*AdministrationEvent_Resource)(nil),      // 9: v1.AdministrationEvent.Resource
	(*timestamppb.Timestamp)(nil),             // 10: google.protobuf.Timestamp
	(*Pagination)(nil),                        // 11: v1.Pagination
	(*ResourceByID)(nil),                      // 12: v1.ResourceByID
}
var file_api_v1_administration_events_service_proto_depIdxs = []int32{
	0,  // 0: v1.AdministrationEvent.type:type_name -> v1.AdministrationEventType
	1,  // 1: v1.AdministrationEvent.level:type_name -> v1.AdministrationEventLevel
	9,  // 2: v1.AdministrationEvent.resource:type_name -> v1.AdministrationEvent.Resource
	10, // 3: v1.AdministrationEvent.last_occurred_at:type_name -> google.protobuf.Timestamp
	10, // 4: v1.AdministrationEvent.created_at:type_name -> google.protobuf.Timestamp
	10, // 5: v1.AdministrationEventsFilter.from:type_name -> google.protobuf.Timestamp
	10, // 6: v1.AdministrationEventsFilter.until:type_name -> google.protobuf.Timestamp
	0,  // 7: v1.AdministrationEventsFilter.type:type_name -> v1.AdministrationEventType
	1,  // 8: v1.AdministrationEventsFilter.level:type_name -> v1.AdministrationEventLevel
	3,  // 9: v1.CountAdministrationEventsRequest.filter:type_name -> v1.AdministrationEventsFilter
	2,  // 10: v1.GetAdministrationEventResponse.event:type_name -> v1.AdministrationEvent
	11, // 11: v1.ListAdministrationEventsRequest.pagination:type_name -> v1.Pagination
	3,  // 12: v1.ListAdministrationEventsRequest.filter:type_name -> v1.AdministrationEventsFilter
	2,  // 13: v1.ListAdministrationEventsResponse.events:type_name -> v1.AdministrationEvent
	4,  // 14: v1.AdministrationEventService.CountAdministrationEvents:input_type -> v1.CountAdministrationEventsRequest
	12, // 15: v1.AdministrationEventService.GetAdministrationEvent:input_type -> v1.ResourceByID
	7,  // 16: v1.AdministrationEventService.ListAdministrationEvents:input_type -> v1.ListAdministrationEventsRequest
	5,  // 17: v1.AdministrationEventService.CountAdministrationEvents:output_type -> v1.CountAdministrationEventsResponse
	6,  // 18: v1.AdministrationEventService.GetAdministrationEvent:output_type -> v1.GetAdministrationEventResponse
	8,  // 19: v1.AdministrationEventService.ListAdministrationEvents:output_type -> v1.ListAdministrationEventsResponse
	17, // [17:20] is the sub-list for method output_type
	14, // [14:17] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_api_v1_administration_events_service_proto_init() }
func file_api_v1_administration_events_service_proto_init() {
	if File_api_v1_administration_events_service_proto != nil {
		return
	}
	file_api_v1_common_proto_init()
	file_api_v1_pagination_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_api_v1_administration_events_service_proto_rawDesc), len(file_api_v1_administration_events_service_proto_rawDesc)),
			NumEnums:      2,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1_administration_events_service_proto_goTypes,
		DependencyIndexes: file_api_v1_administration_events_service_proto_depIdxs,
		EnumInfos:         file_api_v1_administration_events_service_proto_enumTypes,
		MessageInfos:      file_api_v1_administration_events_service_proto_msgTypes,
	}.Build()
	File_api_v1_administration_events_service_proto = out.File
	file_api_v1_administration_events_service_proto_goTypes = nil
	file_api_v1_administration_events_service_proto_depIdxs = nil
}
