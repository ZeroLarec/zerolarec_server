// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.29.3
// source: v1/organization_service.proto

package apiv1

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

type ListOrganizationsRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Limit         int32                  `protobuf:"varint,1,opt,name=limit,proto3" json:"limit,omitempty"`
	Offset        int32                  `protobuf:"varint,2,opt,name=offset,proto3" json:"offset,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListOrganizationsRequest) Reset() {
	*x = ListOrganizationsRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListOrganizationsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListOrganizationsRequest) ProtoMessage() {}

func (x *ListOrganizationsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListOrganizationsRequest.ProtoReflect.Descriptor instead.
func (*ListOrganizationsRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{0}
}

func (x *ListOrganizationsRequest) GetLimit() int32 {
	if x != nil {
		return x.Limit
	}
	return 0
}

func (x *ListOrganizationsRequest) GetOffset() int32 {
	if x != nil {
		return x.Offset
	}
	return 0
}

type ListOrganizationsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Organizations []*Organization        `protobuf:"bytes,1,rep,name=organizations,proto3" json:"organizations,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListOrganizationsResponse) Reset() {
	*x = ListOrganizationsResponse{}
	mi := &file_v1_organization_service_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListOrganizationsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListOrganizationsResponse) ProtoMessage() {}

func (x *ListOrganizationsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListOrganizationsResponse.ProtoReflect.Descriptor instead.
func (*ListOrganizationsResponse) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{1}
}

func (x *ListOrganizationsResponse) GetOrganizations() []*Organization {
	if x != nil {
		return x.Organizations
	}
	return nil
}

type CreateOrganizationRequest struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	Name                  string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Description           string                 `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	ProtectedSymmetricKey string                 `protobuf:"bytes,3,opt,name=protected_symmetric_key,json=protectedSymmetricKey,proto3" json:"protected_symmetric_key,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *CreateOrganizationRequest) Reset() {
	*x = CreateOrganizationRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreateOrganizationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateOrganizationRequest) ProtoMessage() {}

func (x *CreateOrganizationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateOrganizationRequest.ProtoReflect.Descriptor instead.
func (*CreateOrganizationRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{2}
}

func (x *CreateOrganizationRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *CreateOrganizationRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *CreateOrganizationRequest) GetProtectedSymmetricKey() string {
	if x != nil {
		return x.ProtectedSymmetricKey
	}
	return ""
}

type DeleteOrganizationRequest struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	OrganizationId string                 `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *DeleteOrganizationRequest) Reset() {
	*x = DeleteOrganizationRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeleteOrganizationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteOrganizationRequest) ProtoMessage() {}

func (x *DeleteOrganizationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteOrganizationRequest.ProtoReflect.Descriptor instead.
func (*DeleteOrganizationRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{3}
}

func (x *DeleteOrganizationRequest) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

type DeleteOrganizationResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DeleteOrganizationResponse) Reset() {
	*x = DeleteOrganizationResponse{}
	mi := &file_v1_organization_service_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeleteOrganizationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteOrganizationResponse) ProtoMessage() {}

func (x *DeleteOrganizationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteOrganizationResponse.ProtoReflect.Descriptor instead.
func (*DeleteOrganizationResponse) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{4}
}

type ListOrganizationMembersRequest struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	OrganizationId string                 `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	Limit          int32                  `protobuf:"varint,2,opt,name=limit,proto3" json:"limit,omitempty"`
	Offset         int32                  `protobuf:"varint,3,opt,name=offset,proto3" json:"offset,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *ListOrganizationMembersRequest) Reset() {
	*x = ListOrganizationMembersRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListOrganizationMembersRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListOrganizationMembersRequest) ProtoMessage() {}

func (x *ListOrganizationMembersRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListOrganizationMembersRequest.ProtoReflect.Descriptor instead.
func (*ListOrganizationMembersRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{5}
}

func (x *ListOrganizationMembersRequest) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

func (x *ListOrganizationMembersRequest) GetLimit() int32 {
	if x != nil {
		return x.Limit
	}
	return 0
}

func (x *ListOrganizationMembersRequest) GetOffset() int32 {
	if x != nil {
		return x.Offset
	}
	return 0
}

type ListOrganizationMembersResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	UserIds       []string               `protobuf:"bytes,1,rep,name=user_ids,json=userIds,proto3" json:"user_ids,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListOrganizationMembersResponse) Reset() {
	*x = ListOrganizationMembersResponse{}
	mi := &file_v1_organization_service_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListOrganizationMembersResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListOrganizationMembersResponse) ProtoMessage() {}

func (x *ListOrganizationMembersResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListOrganizationMembersResponse.ProtoReflect.Descriptor instead.
func (*ListOrganizationMembersResponse) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{6}
}

func (x *ListOrganizationMembersResponse) GetUserIds() []string {
	if x != nil {
		return x.UserIds
	}
	return nil
}

type GetOrganizationSymmetricKeyRequest struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	OrganizationId string                 `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *GetOrganizationSymmetricKeyRequest) Reset() {
	*x = GetOrganizationSymmetricKeyRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetOrganizationSymmetricKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOrganizationSymmetricKeyRequest) ProtoMessage() {}

func (x *GetOrganizationSymmetricKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOrganizationSymmetricKeyRequest.ProtoReflect.Descriptor instead.
func (*GetOrganizationSymmetricKeyRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{7}
}

func (x *GetOrganizationSymmetricKeyRequest) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

type GetOrganizationSymmetricKeyResponse struct {
	state                             protoimpl.MessageState `protogen:"open.v1"`
	OrganizationSymmetricKeyProtected []byte                 `protobuf:"bytes,3,opt,name=organization_symmetric_key_protected,json=organizationSymmetricKeyProtected,proto3" json:"organization_symmetric_key_protected,omitempty"`
	unknownFields                     protoimpl.UnknownFields
	sizeCache                         protoimpl.SizeCache
}

func (x *GetOrganizationSymmetricKeyResponse) Reset() {
	*x = GetOrganizationSymmetricKeyResponse{}
	mi := &file_v1_organization_service_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetOrganizationSymmetricKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOrganizationSymmetricKeyResponse) ProtoMessage() {}

func (x *GetOrganizationSymmetricKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOrganizationSymmetricKeyResponse.ProtoReflect.Descriptor instead.
func (*GetOrganizationSymmetricKeyResponse) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{8}
}

func (x *GetOrganizationSymmetricKeyResponse) GetOrganizationSymmetricKeyProtected() []byte {
	if x != nil {
		return x.OrganizationSymmetricKeyProtected
	}
	return nil
}

type AddUserToOrganizationRequest struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	OrganizationId        string                 `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	UserId                string                 `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	ProtectedSymmetricKey string                 `protobuf:"bytes,3,opt,name=protected_symmetric_key,json=protectedSymmetricKey,proto3" json:"protected_symmetric_key,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *AddUserToOrganizationRequest) Reset() {
	*x = AddUserToOrganizationRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AddUserToOrganizationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddUserToOrganizationRequest) ProtoMessage() {}

func (x *AddUserToOrganizationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddUserToOrganizationRequest.ProtoReflect.Descriptor instead.
func (*AddUserToOrganizationRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{9}
}

func (x *AddUserToOrganizationRequest) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

func (x *AddUserToOrganizationRequest) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *AddUserToOrganizationRequest) GetProtectedSymmetricKey() string {
	if x != nil {
		return x.ProtectedSymmetricKey
	}
	return ""
}

type AddUserToOrganizationResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AddUserToOrganizationResponse) Reset() {
	*x = AddUserToOrganizationResponse{}
	mi := &file_v1_organization_service_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AddUserToOrganizationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddUserToOrganizationResponse) ProtoMessage() {}

func (x *AddUserToOrganizationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddUserToOrganizationResponse.ProtoReflect.Descriptor instead.
func (*AddUserToOrganizationResponse) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{10}
}

type RemoveUserFromOrganizationRequest struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	OrganizationId string                 `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	UserId         string                 `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *RemoveUserFromOrganizationRequest) Reset() {
	*x = RemoveUserFromOrganizationRequest{}
	mi := &file_v1_organization_service_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RemoveUserFromOrganizationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemoveUserFromOrganizationRequest) ProtoMessage() {}

func (x *RemoveUserFromOrganizationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemoveUserFromOrganizationRequest.ProtoReflect.Descriptor instead.
func (*RemoveUserFromOrganizationRequest) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{11}
}

func (x *RemoveUserFromOrganizationRequest) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

func (x *RemoveUserFromOrganizationRequest) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

type RemoveUserFromOrganizationResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RemoveUserFromOrganizationResponse) Reset() {
	*x = RemoveUserFromOrganizationResponse{}
	mi := &file_v1_organization_service_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RemoveUserFromOrganizationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemoveUserFromOrganizationResponse) ProtoMessage() {}

func (x *RemoveUserFromOrganizationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemoveUserFromOrganizationResponse.ProtoReflect.Descriptor instead.
func (*RemoveUserFromOrganizationResponse) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{12}
}

type Organization struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	OrganizationId string                 `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	Name           string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description    string                 `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *Organization) Reset() {
	*x = Organization{}
	mi := &file_v1_organization_service_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Organization) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Organization) ProtoMessage() {}

func (x *Organization) ProtoReflect() protoreflect.Message {
	mi := &file_v1_organization_service_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Organization.ProtoReflect.Descriptor instead.
func (*Organization) Descriptor() ([]byte, []int) {
	return file_v1_organization_service_proto_rawDescGZIP(), []int{13}
}

func (x *Organization) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

func (x *Organization) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Organization) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

var File_v1_organization_service_proto protoreflect.FileDescriptor

var file_v1_organization_service_proto_rawDesc = string([]byte{
	0x0a, 0x1d, 0x76, 0x31, 0x2f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x05, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x22, 0x48, 0x0a, 0x18, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73,
	0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74,
	0x22, 0x56, 0x0a, 0x19, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x39, 0x0a,
	0x0d, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x4f, 0x72, 0x67,
	0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0d, 0x6f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x89, 0x01, 0x0a, 0x19, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x36, 0x0a, 0x17,
	0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x79, 0x6d, 0x6d, 0x65, 0x74,
	0x72, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x70,
	0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x22, 0x44, 0x0a, 0x19, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x27, 0x0a, 0x0f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61,
	0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x22, 0x1c, 0x0a, 0x1a, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x77, 0x0a, 0x1e, 0x4c, 0x69, 0x73, 0x74,
	0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x6d, 0x62,
	0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x6f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66,
	0x73, 0x65, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65,
	0x74, 0x22, 0x3c, 0x0a, 0x1f, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x73, 0x22,
	0x4d, 0x0a, 0x22, 0x47, 0x65, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x22, 0x76,
	0x0a, 0x23, 0x47, 0x65, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4f, 0x0a, 0x24, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x5f,
	0x6b, 0x65, 0x79, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x21, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f,
	0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x22, 0x98, 0x01, 0x0a, 0x1c, 0x41, 0x64, 0x64, 0x55, 0x73,
	0x65, 0x72, 0x54, 0x6f, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x6f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64,
	0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x36, 0x0a, 0x17, 0x70, 0x72, 0x6f,
	0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x70, 0x72, 0x6f, 0x74,
	0x65, 0x63, 0x74, 0x65, 0x64, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65,
	0x79, 0x22, 0x1f, 0x0a, 0x1d, 0x41, 0x64, 0x64, 0x55, 0x73, 0x65, 0x72, 0x54, 0x6f, 0x4f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x65, 0x0a, 0x21, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x55, 0x73, 0x65, 0x72,
	0x46, 0x72, 0x6f, 0x6d, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x6f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64,
	0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x22, 0x24, 0x0a, 0x22, 0x52, 0x65, 0x6d,
	0x6f, 0x76, 0x65, 0x55, 0x73, 0x65, 0x72, 0x46, 0x72, 0x6f, 0x6d, 0x4f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x6d, 0x0a, 0x0c, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x27, 0x0a, 0x0f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69,
	0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x32, 0xcc,
	0x05, 0x0a, 0x13, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x56, 0x0a, 0x11, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x1f, 0x2e, 0x6c, 0x61,
	0x72, 0x65, 0x63, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20, 0x2e, 0x6c,
	0x61, 0x72, 0x65, 0x63, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4b,
	0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x20, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x4f,
	0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x59, 0x0a, 0x12, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x20, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x68, 0x0a, 0x17, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72,
	0x73, 0x12, 0x25, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63,
	0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x74, 0x0a, 0x1b, 0x47, 0x65, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12,
	0x29, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x47, 0x65, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e, 0x6c, 0x61, 0x72,
	0x65, 0x63, 0x2e, 0x47, 0x65, 0x74, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x53, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x62, 0x0a, 0x15, 0x41, 0x64, 0x64, 0x55, 0x73, 0x65,
	0x72, 0x54, 0x6f, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x23, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x41, 0x64, 0x64, 0x55, 0x73, 0x65, 0x72, 0x54,
	0x6f, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x41, 0x64, 0x64,
	0x55, 0x73, 0x65, 0x72, 0x54, 0x6f, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x71, 0x0a, 0x1a, 0x52, 0x65,
	0x6d, 0x6f, 0x76, 0x65, 0x55, 0x73, 0x65, 0x72, 0x46, 0x72, 0x6f, 0x6d, 0x4f, 0x72, 0x67, 0x61,
	0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x28, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63,
	0x2e, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x55, 0x73, 0x65, 0x72, 0x46, 0x72, 0x6f, 0x6d, 0x4f,
	0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x29, 0x2e, 0x6c, 0x61, 0x72, 0x65, 0x63, 0x2e, 0x52, 0x65, 0x6d, 0x6f, 0x76,
	0x65, 0x55, 0x73, 0x65, 0x72, 0x46, 0x72, 0x6f, 0x6d, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x08, 0x5a,
	0x06, 0x2f, 0x61, 0x70, 0x69, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_v1_organization_service_proto_rawDescOnce sync.Once
	file_v1_organization_service_proto_rawDescData []byte
)

func file_v1_organization_service_proto_rawDescGZIP() []byte {
	file_v1_organization_service_proto_rawDescOnce.Do(func() {
		file_v1_organization_service_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_v1_organization_service_proto_rawDesc), len(file_v1_organization_service_proto_rawDesc)))
	})
	return file_v1_organization_service_proto_rawDescData
}

var file_v1_organization_service_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_v1_organization_service_proto_goTypes = []any{
	(*ListOrganizationsRequest)(nil),            // 0: larec.ListOrganizationsRequest
	(*ListOrganizationsResponse)(nil),           // 1: larec.ListOrganizationsResponse
	(*CreateOrganizationRequest)(nil),           // 2: larec.CreateOrganizationRequest
	(*DeleteOrganizationRequest)(nil),           // 3: larec.DeleteOrganizationRequest
	(*DeleteOrganizationResponse)(nil),          // 4: larec.DeleteOrganizationResponse
	(*ListOrganizationMembersRequest)(nil),      // 5: larec.ListOrganizationMembersRequest
	(*ListOrganizationMembersResponse)(nil),     // 6: larec.ListOrganizationMembersResponse
	(*GetOrganizationSymmetricKeyRequest)(nil),  // 7: larec.GetOrganizationSymmetricKeyRequest
	(*GetOrganizationSymmetricKeyResponse)(nil), // 8: larec.GetOrganizationSymmetricKeyResponse
	(*AddUserToOrganizationRequest)(nil),        // 9: larec.AddUserToOrganizationRequest
	(*AddUserToOrganizationResponse)(nil),       // 10: larec.AddUserToOrganizationResponse
	(*RemoveUserFromOrganizationRequest)(nil),   // 11: larec.RemoveUserFromOrganizationRequest
	(*RemoveUserFromOrganizationResponse)(nil),  // 12: larec.RemoveUserFromOrganizationResponse
	(*Organization)(nil),                        // 13: larec.Organization
}
var file_v1_organization_service_proto_depIdxs = []int32{
	13, // 0: larec.ListOrganizationsResponse.organizations:type_name -> larec.Organization
	0,  // 1: larec.OrganizationService.ListOrganizations:input_type -> larec.ListOrganizationsRequest
	2,  // 2: larec.OrganizationService.CreateOrganization:input_type -> larec.CreateOrganizationRequest
	3,  // 3: larec.OrganizationService.DeleteOrganization:input_type -> larec.DeleteOrganizationRequest
	5,  // 4: larec.OrganizationService.ListOrganizationMembers:input_type -> larec.ListOrganizationMembersRequest
	7,  // 5: larec.OrganizationService.GetOrganizationSymmetricKey:input_type -> larec.GetOrganizationSymmetricKeyRequest
	9,  // 6: larec.OrganizationService.AddUserToOrganization:input_type -> larec.AddUserToOrganizationRequest
	11, // 7: larec.OrganizationService.RemoveUserFromOrganization:input_type -> larec.RemoveUserFromOrganizationRequest
	1,  // 8: larec.OrganizationService.ListOrganizations:output_type -> larec.ListOrganizationsResponse
	13, // 9: larec.OrganizationService.CreateOrganization:output_type -> larec.Organization
	4,  // 10: larec.OrganizationService.DeleteOrganization:output_type -> larec.DeleteOrganizationResponse
	6,  // 11: larec.OrganizationService.ListOrganizationMembers:output_type -> larec.ListOrganizationMembersResponse
	8,  // 12: larec.OrganizationService.GetOrganizationSymmetricKey:output_type -> larec.GetOrganizationSymmetricKeyResponse
	10, // 13: larec.OrganizationService.AddUserToOrganization:output_type -> larec.AddUserToOrganizationResponse
	12, // 14: larec.OrganizationService.RemoveUserFromOrganization:output_type -> larec.RemoveUserFromOrganizationResponse
	8,  // [8:15] is the sub-list for method output_type
	1,  // [1:8] is the sub-list for method input_type
	1,  // [1:1] is the sub-list for extension type_name
	1,  // [1:1] is the sub-list for extension extendee
	0,  // [0:1] is the sub-list for field type_name
}

func init() { file_v1_organization_service_proto_init() }
func file_v1_organization_service_proto_init() {
	if File_v1_organization_service_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_v1_organization_service_proto_rawDesc), len(file_v1_organization_service_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_v1_organization_service_proto_goTypes,
		DependencyIndexes: file_v1_organization_service_proto_depIdxs,
		MessageInfos:      file_v1_organization_service_proto_msgTypes,
	}.Build()
	File_v1_organization_service_proto = out.File
	file_v1_organization_service_proto_goTypes = nil
	file_v1_organization_service_proto_depIdxs = nil
}
