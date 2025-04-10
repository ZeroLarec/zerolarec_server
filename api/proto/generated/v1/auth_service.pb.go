// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: v1/auth_service.proto

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

type RegisterRequest struct {
	state                  protoimpl.MessageState `protogen:"open.v1"`
	Login                  string                 `protobuf:"bytes,1,opt,name=login,proto3" json:"login,omitempty"`
	AuthenticatePassword   []byte                 `protobuf:"bytes,2,opt,name=authenticate_password,json=authenticatePassword,proto3" json:"authenticate_password,omitempty"`
	RsaPublicKey           []byte                 `protobuf:"bytes,3,opt,name=rsa_public_key,json=rsaPublicKey,proto3" json:"rsa_public_key,omitempty"`
	RsaPrivateKeyProtected []byte                 `protobuf:"bytes,4,opt,name=rsa_private_key_protected,json=rsaPrivateKeyProtected,proto3" json:"rsa_private_key_protected,omitempty"`
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *RegisterRequest) Reset() {
	*x = RegisterRequest{}
	mi := &file_v1_auth_service_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegisterRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterRequest) ProtoMessage() {}

func (x *RegisterRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_auth_service_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterRequest.ProtoReflect.Descriptor instead.
func (*RegisterRequest) Descriptor() ([]byte, []int) {
	return file_v1_auth_service_proto_rawDescGZIP(), []int{0}
}

func (x *RegisterRequest) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

func (x *RegisterRequest) GetAuthenticatePassword() []byte {
	if x != nil {
		return x.AuthenticatePassword
	}
	return nil
}

func (x *RegisterRequest) GetRsaPublicKey() []byte {
	if x != nil {
		return x.RsaPublicKey
	}
	return nil
}

func (x *RegisterRequest) GetRsaPrivateKeyProtected() []byte {
	if x != nil {
		return x.RsaPrivateKeyProtected
	}
	return nil
}

type RegisterResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	UserId        string                 `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RegisterResponse) Reset() {
	*x = RegisterResponse{}
	mi := &file_v1_auth_service_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegisterResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterResponse) ProtoMessage() {}

func (x *RegisterResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_auth_service_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterResponse.ProtoReflect.Descriptor instead.
func (*RegisterResponse) Descriptor() ([]byte, []int) {
	return file_v1_auth_service_proto_rawDescGZIP(), []int{1}
}

func (x *RegisterResponse) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

type LoginRequest struct {
	state                protoimpl.MessageState `protogen:"open.v1"`
	Login                string                 `protobuf:"bytes,1,opt,name=login,proto3" json:"login,omitempty"`
	AuthenticatePassword []byte                 `protobuf:"bytes,2,opt,name=authenticate_password,json=authenticatePassword,proto3" json:"authenticate_password,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *LoginRequest) Reset() {
	*x = LoginRequest{}
	mi := &file_v1_auth_service_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LoginRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginRequest) ProtoMessage() {}

func (x *LoginRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_auth_service_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginRequest.ProtoReflect.Descriptor instead.
func (*LoginRequest) Descriptor() ([]byte, []int) {
	return file_v1_auth_service_proto_rawDescGZIP(), []int{2}
}

func (x *LoginRequest) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

func (x *LoginRequest) GetAuthenticatePassword() []byte {
	if x != nil {
		return x.AuthenticatePassword
	}
	return nil
}

type LoginResponse struct {
	state                  protoimpl.MessageState `protogen:"open.v1"`
	UserId                 string                 `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	RsaPrivateKeyProtected []byte                 `protobuf:"bytes,2,opt,name=rsa_private_key_protected,json=rsaPrivateKeyProtected,proto3" json:"rsa_private_key_protected,omitempty"`
	AccessToken            string                 `protobuf:"bytes,3,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *LoginResponse) Reset() {
	*x = LoginResponse{}
	mi := &file_v1_auth_service_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LoginResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginResponse) ProtoMessage() {}

func (x *LoginResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_auth_service_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginResponse.ProtoReflect.Descriptor instead.
func (*LoginResponse) Descriptor() ([]byte, []int) {
	return file_v1_auth_service_proto_rawDescGZIP(), []int{3}
}

func (x *LoginResponse) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *LoginResponse) GetRsaPrivateKeyProtected() []byte {
	if x != nil {
		return x.RsaPrivateKeyProtected
	}
	return nil
}

func (x *LoginResponse) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

type LogoutRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AccessToken   string                 `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogoutRequest) Reset() {
	*x = LogoutRequest{}
	mi := &file_v1_auth_service_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogoutRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogoutRequest) ProtoMessage() {}

func (x *LogoutRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_auth_service_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogoutRequest.ProtoReflect.Descriptor instead.
func (*LogoutRequest) Descriptor() ([]byte, []int) {
	return file_v1_auth_service_proto_rawDescGZIP(), []int{4}
}

func (x *LogoutRequest) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

type LogoutResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogoutResponse) Reset() {
	*x = LogoutResponse{}
	mi := &file_v1_auth_service_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogoutResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogoutResponse) ProtoMessage() {}

func (x *LogoutResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_auth_service_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogoutResponse.ProtoReflect.Descriptor instead.
func (*LogoutResponse) Descriptor() ([]byte, []int) {
	return file_v1_auth_service_proto_rawDescGZIP(), []int{5}
}

var File_v1_auth_service_proto protoreflect.FileDescriptor

const file_v1_auth_service_proto_rawDesc = "" +
	"\n" +
	"\x15v1/auth_service.proto\x12\x05larec\"\xbd\x01\n" +
	"\x0fRegisterRequest\x12\x14\n" +
	"\x05login\x18\x01 \x01(\tR\x05login\x123\n" +
	"\x15authenticate_password\x18\x02 \x01(\fR\x14authenticatePassword\x12$\n" +
	"\x0ersa_public_key\x18\x03 \x01(\fR\frsaPublicKey\x129\n" +
	"\x19rsa_private_key_protected\x18\x04 \x01(\fR\x16rsaPrivateKeyProtected\"+\n" +
	"\x10RegisterResponse\x12\x17\n" +
	"\auser_id\x18\x01 \x01(\tR\x06userId\"Y\n" +
	"\fLoginRequest\x12\x14\n" +
	"\x05login\x18\x01 \x01(\tR\x05login\x123\n" +
	"\x15authenticate_password\x18\x02 \x01(\fR\x14authenticatePassword\"\x86\x01\n" +
	"\rLoginResponse\x12\x17\n" +
	"\auser_id\x18\x01 \x01(\tR\x06userId\x129\n" +
	"\x19rsa_private_key_protected\x18\x02 \x01(\fR\x16rsaPrivateKeyProtected\x12!\n" +
	"\faccess_token\x18\x03 \x01(\tR\vaccessToken\"2\n" +
	"\rLogoutRequest\x12!\n" +
	"\faccess_token\x18\x01 \x01(\tR\vaccessToken\"\x10\n" +
	"\x0eLogoutResponse2\xbd\x01\n" +
	"\x13AuthenticateService\x12;\n" +
	"\bRegister\x12\x16.larec.RegisterRequest\x1a\x17.larec.RegisterResponse\x122\n" +
	"\x05Login\x12\x13.larec.LoginRequest\x1a\x14.larec.LoginResponse\x125\n" +
	"\x06Logout\x12\x14.larec.LogoutRequest\x1a\x15.larec.LogoutResponseB\bZ\x06/apiv1b\x06proto3"

var (
	file_v1_auth_service_proto_rawDescOnce sync.Once
	file_v1_auth_service_proto_rawDescData []byte
)

func file_v1_auth_service_proto_rawDescGZIP() []byte {
	file_v1_auth_service_proto_rawDescOnce.Do(func() {
		file_v1_auth_service_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_v1_auth_service_proto_rawDesc), len(file_v1_auth_service_proto_rawDesc)))
	})
	return file_v1_auth_service_proto_rawDescData
}

var file_v1_auth_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_v1_auth_service_proto_goTypes = []any{
	(*RegisterRequest)(nil),  // 0: larec.RegisterRequest
	(*RegisterResponse)(nil), // 1: larec.RegisterResponse
	(*LoginRequest)(nil),     // 2: larec.LoginRequest
	(*LoginResponse)(nil),    // 3: larec.LoginResponse
	(*LogoutRequest)(nil),    // 4: larec.LogoutRequest
	(*LogoutResponse)(nil),   // 5: larec.LogoutResponse
}
var file_v1_auth_service_proto_depIdxs = []int32{
	0, // 0: larec.AuthenticateService.Register:input_type -> larec.RegisterRequest
	2, // 1: larec.AuthenticateService.Login:input_type -> larec.LoginRequest
	4, // 2: larec.AuthenticateService.Logout:input_type -> larec.LogoutRequest
	1, // 3: larec.AuthenticateService.Register:output_type -> larec.RegisterResponse
	3, // 4: larec.AuthenticateService.Login:output_type -> larec.LoginResponse
	5, // 5: larec.AuthenticateService.Logout:output_type -> larec.LogoutResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_v1_auth_service_proto_init() }
func file_v1_auth_service_proto_init() {
	if File_v1_auth_service_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_v1_auth_service_proto_rawDesc), len(file_v1_auth_service_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_v1_auth_service_proto_goTypes,
		DependencyIndexes: file_v1_auth_service_proto_depIdxs,
		MessageInfos:      file_v1_auth_service_proto_msgTypes,
	}.Build()
	File_v1_auth_service_proto = out.File
	file_v1_auth_service_proto_goTypes = nil
	file_v1_auth_service_proto_depIdxs = nil
}
