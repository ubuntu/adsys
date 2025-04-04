// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.4
// 	protoc        v4.23.4
// source: adsys.proto

package adsys

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

type Empty struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Empty) Reset() {
	*x = Empty{}
	mi := &file_adsys_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{0}
}

type ListUsersRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Active        bool                   `protobuf:"varint,1,opt,name=active,proto3" json:"active,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListUsersRequest) Reset() {
	*x = ListUsersRequest{}
	mi := &file_adsys_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListUsersRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListUsersRequest) ProtoMessage() {}

func (x *ListUsersRequest) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListUsersRequest.ProtoReflect.Descriptor instead.
func (*ListUsersRequest) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{1}
}

func (x *ListUsersRequest) GetActive() bool {
	if x != nil {
		return x.Active
	}
	return false
}

type StopRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Force         bool                   `protobuf:"varint,1,opt,name=force,proto3" json:"force,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StopRequest) Reset() {
	*x = StopRequest{}
	mi := &file_adsys_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StopRequest) ProtoMessage() {}

func (x *StopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StopRequest.ProtoReflect.Descriptor instead.
func (*StopRequest) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{2}
}

func (x *StopRequest) GetForce() bool {
	if x != nil {
		return x.Force
	}
	return false
}

type StringResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Msg           string                 `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StringResponse) Reset() {
	*x = StringResponse{}
	mi := &file_adsys_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StringResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StringResponse) ProtoMessage() {}

func (x *StringResponse) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StringResponse.ProtoReflect.Descriptor instead.
func (*StringResponse) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{3}
}

func (x *StringResponse) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

type UpdatePolicyRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	IsComputer    bool                   `protobuf:"varint,1,opt,name=isComputer,proto3" json:"isComputer,omitempty"`
	All           bool                   `protobuf:"varint,2,opt,name=all,proto3" json:"all,omitempty"` // Update policies of the machine and all the users
	Target        string                 `protobuf:"bytes,3,opt,name=target,proto3" json:"target,omitempty"`
	Krb5Cc        string                 `protobuf:"bytes,4,opt,name=krb5cc,proto3" json:"krb5cc,omitempty"`
	Purge         bool                   `protobuf:"varint,5,opt,name=purge,proto3" json:"purge,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UpdatePolicyRequest) Reset() {
	*x = UpdatePolicyRequest{}
	mi := &file_adsys_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UpdatePolicyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdatePolicyRequest) ProtoMessage() {}

func (x *UpdatePolicyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdatePolicyRequest.ProtoReflect.Descriptor instead.
func (*UpdatePolicyRequest) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{4}
}

func (x *UpdatePolicyRequest) GetIsComputer() bool {
	if x != nil {
		return x.IsComputer
	}
	return false
}

func (x *UpdatePolicyRequest) GetAll() bool {
	if x != nil {
		return x.All
	}
	return false
}

func (x *UpdatePolicyRequest) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *UpdatePolicyRequest) GetKrb5Cc() string {
	if x != nil {
		return x.Krb5Cc
	}
	return ""
}

func (x *UpdatePolicyRequest) GetPurge() bool {
	if x != nil {
		return x.Purge
	}
	return false
}

type DumpPoliciesRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Target        string                 `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
	IsComputer    bool                   `protobuf:"varint,2,opt,name=isComputer,proto3" json:"isComputer,omitempty"`
	Details       bool                   `protobuf:"varint,3,opt,name=details,proto3" json:"details,omitempty"` // Show rules in addition to GPO
	All           bool                   `protobuf:"varint,4,opt,name=all,proto3" json:"all,omitempty"`         // Show overridden rules
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DumpPoliciesRequest) Reset() {
	*x = DumpPoliciesRequest{}
	mi := &file_adsys_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DumpPoliciesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DumpPoliciesRequest) ProtoMessage() {}

func (x *DumpPoliciesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DumpPoliciesRequest.ProtoReflect.Descriptor instead.
func (*DumpPoliciesRequest) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{5}
}

func (x *DumpPoliciesRequest) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *DumpPoliciesRequest) GetIsComputer() bool {
	if x != nil {
		return x.IsComputer
	}
	return false
}

func (x *DumpPoliciesRequest) GetDetails() bool {
	if x != nil {
		return x.Details
	}
	return false
}

func (x *DumpPoliciesRequest) GetAll() bool {
	if x != nil {
		return x.All
	}
	return false
}

type DumpPolicyDefinitionsRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Format        string                 `protobuf:"bytes,1,opt,name=format,proto3" json:"format,omitempty"`
	DistroID      string                 `protobuf:"bytes,2,opt,name=distroID,proto3" json:"distroID,omitempty"` // Force another distro than the built-in one
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DumpPolicyDefinitionsRequest) Reset() {
	*x = DumpPolicyDefinitionsRequest{}
	mi := &file_adsys_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DumpPolicyDefinitionsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DumpPolicyDefinitionsRequest) ProtoMessage() {}

func (x *DumpPolicyDefinitionsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DumpPolicyDefinitionsRequest.ProtoReflect.Descriptor instead.
func (*DumpPolicyDefinitionsRequest) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{6}
}

func (x *DumpPolicyDefinitionsRequest) GetFormat() string {
	if x != nil {
		return x.Format
	}
	return ""
}

func (x *DumpPolicyDefinitionsRequest) GetDistroID() string {
	if x != nil {
		return x.DistroID
	}
	return ""
}

type DumpPolicyDefinitionsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Admx          string                 `protobuf:"bytes,1,opt,name=admx,proto3" json:"admx,omitempty"`
	Adml          string                 `protobuf:"bytes,2,opt,name=adml,proto3" json:"adml,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DumpPolicyDefinitionsResponse) Reset() {
	*x = DumpPolicyDefinitionsResponse{}
	mi := &file_adsys_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DumpPolicyDefinitionsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DumpPolicyDefinitionsResponse) ProtoMessage() {}

func (x *DumpPolicyDefinitionsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DumpPolicyDefinitionsResponse.ProtoReflect.Descriptor instead.
func (*DumpPolicyDefinitionsResponse) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{7}
}

func (x *DumpPolicyDefinitionsResponse) GetAdmx() string {
	if x != nil {
		return x.Admx
	}
	return ""
}

func (x *DumpPolicyDefinitionsResponse) GetAdml() string {
	if x != nil {
		return x.Adml
	}
	return ""
}

type GetDocRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Chapter       string                 `protobuf:"bytes,1,opt,name=chapter,proto3" json:"chapter,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetDocRequest) Reset() {
	*x = GetDocRequest{}
	mi := &file_adsys_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetDocRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetDocRequest) ProtoMessage() {}

func (x *GetDocRequest) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetDocRequest.ProtoReflect.Descriptor instead.
func (*GetDocRequest) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{8}
}

func (x *GetDocRequest) GetChapter() string {
	if x != nil {
		return x.Chapter
	}
	return ""
}

type ListDocReponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Chapters      []string               `protobuf:"bytes,1,rep,name=chapters,proto3" json:"chapters,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListDocReponse) Reset() {
	*x = ListDocReponse{}
	mi := &file_adsys_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListDocReponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListDocReponse) ProtoMessage() {}

func (x *ListDocReponse) ProtoReflect() protoreflect.Message {
	mi := &file_adsys_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListDocReponse.ProtoReflect.Descriptor instead.
func (*ListDocReponse) Descriptor() ([]byte, []int) {
	return file_adsys_proto_rawDescGZIP(), []int{9}
}

func (x *ListDocReponse) GetChapters() []string {
	if x != nil {
		return x.Chapters
	}
	return nil
}

var File_adsys_proto protoreflect.FileDescriptor

var file_adsys_proto_rawDesc = string([]byte{
	0x0a, 0x0b, 0x61, 0x64, 0x73, 0x79, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x07, 0x0a,
	0x05, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x2a, 0x0a, 0x10, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73,
	0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x63,
	0x74, 0x69, 0x76, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x61, 0x63, 0x74, 0x69,
	0x76, 0x65, 0x22, 0x23, 0x0a, 0x0b, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x14, 0x0a, 0x05, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x05, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x22, 0x22, 0x0a, 0x0e, 0x53, 0x74, 0x72, 0x69, 0x6e,
	0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x22, 0x8d, 0x01, 0x0a, 0x13,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x69, 0x73, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x69, 0x73, 0x43, 0x6f, 0x6d, 0x70, 0x75,
	0x74, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x6c, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x03, 0x61, 0x6c, 0x6c, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x6b, 0x72, 0x62, 0x35, 0x63, 0x63, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6b,
	0x72, 0x62, 0x35, 0x63, 0x63, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x75, 0x72, 0x67, 0x65, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x70, 0x75, 0x72, 0x67, 0x65, 0x22, 0x79, 0x0a, 0x13, 0x44,
	0x75, 0x6d, 0x70, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x69, 0x73,
	0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a,
	0x69, 0x73, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x64, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x6c, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x03, 0x61, 0x6c, 0x6c, 0x22, 0x52, 0x0a, 0x1c, 0x44, 0x75, 0x6d, 0x70, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12, 0x1a,
	0x0a, 0x08, 0x64, 0x69, 0x73, 0x74, 0x72, 0x6f, 0x49, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x64, 0x69, 0x73, 0x74, 0x72, 0x6f, 0x49, 0x44, 0x22, 0x47, 0x0a, 0x1d, 0x44, 0x75,
	0x6d, 0x70, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x61,
	0x64, 0x6d, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x64, 0x6d, 0x78, 0x12,
	0x12, 0x0a, 0x04, 0x61, 0x64, 0x6d, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61,
	0x64, 0x6d, 0x6c, 0x22, 0x29, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x44, 0x6f, 0x63, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x22, 0x2c,
	0x0a, 0x0e, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x6f, 0x63, 0x52, 0x65, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x1a, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x08, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x73, 0x32, 0xc0, 0x04, 0x0a,
	0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x20, 0x0a, 0x03, 0x43, 0x61, 0x74, 0x12,
	0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x24, 0x0a, 0x07, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0f, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01,
	0x12, 0x23, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x1e, 0x0a, 0x04, 0x53, 0x74, 0x6f, 0x70, 0x12, 0x0c, 0x2e,
	0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x06, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x30, 0x01, 0x12, 0x2e, 0x0a, 0x0c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x14, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x06, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x30, 0x01, 0x12, 0x37, 0x0a, 0x0c, 0x44, 0x75, 0x6d, 0x70, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x69, 0x65, 0x73, 0x12, 0x14, 0x2e, 0x44, 0x75, 0x6d, 0x70, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0f, 0x2e, 0x53, 0x74,
	0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x5a,
	0x0a, 0x17, 0x44, 0x75, 0x6d, 0x70, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x44, 0x65,
	0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x1d, 0x2e, 0x44, 0x75, 0x6d, 0x70,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x44, 0x75, 0x6d, 0x70, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x2b, 0x0a, 0x06, 0x47, 0x65,
	0x74, 0x44, 0x6f, 0x63, 0x12, 0x0e, 0x2e, 0x47, 0x65, 0x74, 0x44, 0x6f, 0x63, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x0f, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x24, 0x0a, 0x07, 0x4c, 0x69, 0x73, 0x74, 0x44,
	0x6f, 0x63, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x4c, 0x69, 0x73,
	0x74, 0x44, 0x6f, 0x63, 0x52, 0x65, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x31, 0x0a,
	0x09, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x73, 0x12, 0x11, 0x2e, 0x4c, 0x69, 0x73,
	0x74, 0x55, 0x73, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0f, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01,
	0x12, 0x2a, 0x0a, 0x0d, 0x47, 0x50, 0x4f, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x31, 0x0a, 0x14,
	0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x6f, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x53, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0f, 0x2e, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x42,
	0x19, 0x5a, 0x17, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x75, 0x62,
	0x75, 0x6e, 0x74, 0x75, 0x2f, 0x61, 0x64, 0x73, 0x79, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
})

var (
	file_adsys_proto_rawDescOnce sync.Once
	file_adsys_proto_rawDescData []byte
)

func file_adsys_proto_rawDescGZIP() []byte {
	file_adsys_proto_rawDescOnce.Do(func() {
		file_adsys_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_adsys_proto_rawDesc), len(file_adsys_proto_rawDesc)))
	})
	return file_adsys_proto_rawDescData
}

var file_adsys_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_adsys_proto_goTypes = []any{
	(*Empty)(nil),                         // 0: Empty
	(*ListUsersRequest)(nil),              // 1: ListUsersRequest
	(*StopRequest)(nil),                   // 2: StopRequest
	(*StringResponse)(nil),                // 3: StringResponse
	(*UpdatePolicyRequest)(nil),           // 4: UpdatePolicyRequest
	(*DumpPoliciesRequest)(nil),           // 5: DumpPoliciesRequest
	(*DumpPolicyDefinitionsRequest)(nil),  // 6: DumpPolicyDefinitionsRequest
	(*DumpPolicyDefinitionsResponse)(nil), // 7: DumpPolicyDefinitionsResponse
	(*GetDocRequest)(nil),                 // 8: GetDocRequest
	(*ListDocReponse)(nil),                // 9: ListDocReponse
}
var file_adsys_proto_depIdxs = []int32{
	0,  // 0: service.Cat:input_type -> Empty
	0,  // 1: service.Version:input_type -> Empty
	0,  // 2: service.Status:input_type -> Empty
	2,  // 3: service.Stop:input_type -> StopRequest
	4,  // 4: service.UpdatePolicy:input_type -> UpdatePolicyRequest
	5,  // 5: service.DumpPolicies:input_type -> DumpPoliciesRequest
	6,  // 6: service.DumpPoliciesDefinitions:input_type -> DumpPolicyDefinitionsRequest
	8,  // 7: service.GetDoc:input_type -> GetDocRequest
	0,  // 8: service.ListDoc:input_type -> Empty
	1,  // 9: service.ListUsers:input_type -> ListUsersRequest
	0,  // 10: service.GPOListScript:input_type -> Empty
	0,  // 11: service.CertAutoEnrollScript:input_type -> Empty
	3,  // 12: service.Cat:output_type -> StringResponse
	3,  // 13: service.Version:output_type -> StringResponse
	3,  // 14: service.Status:output_type -> StringResponse
	0,  // 15: service.Stop:output_type -> Empty
	0,  // 16: service.UpdatePolicy:output_type -> Empty
	3,  // 17: service.DumpPolicies:output_type -> StringResponse
	7,  // 18: service.DumpPoliciesDefinitions:output_type -> DumpPolicyDefinitionsResponse
	3,  // 19: service.GetDoc:output_type -> StringResponse
	9,  // 20: service.ListDoc:output_type -> ListDocReponse
	3,  // 21: service.ListUsers:output_type -> StringResponse
	3,  // 22: service.GPOListScript:output_type -> StringResponse
	3,  // 23: service.CertAutoEnrollScript:output_type -> StringResponse
	12, // [12:24] is the sub-list for method output_type
	0,  // [0:12] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_adsys_proto_init() }
func file_adsys_proto_init() {
	if File_adsys_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_adsys_proto_rawDesc), len(file_adsys_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_adsys_proto_goTypes,
		DependencyIndexes: file_adsys_proto_depIdxs,
		MessageInfos:      file_adsys_proto_msgTypes,
	}.Build()
	File_adsys_proto = out.File
	file_adsys_proto_goTypes = nil
	file_adsys_proto_depIdxs = nil
}
