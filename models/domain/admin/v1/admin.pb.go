// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: admin/v1/admin.proto

package adminv1

import (
	bytes "bytes"
	utils "github.com/amaury95/protoc-gen-go-tag/utils"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Admin struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// key represents the unique identifier of the admin
	Key string `protobuf:"bytes,1,opt,name=_key,proto3" json:"_key,omitempty"`
	// sub represents the unique identifier of the authenticator
	Subject string `protobuf:"bytes,2,opt,name=sub,proto3" json:"sub,omitempty"`
	// first name of the admin
	FirstName string `protobuf:"bytes,3,opt,name=firstName,proto3" json:"firstName,omitempty"`
	// last name of the admin
	LastName string `protobuf:"bytes,4,opt,name=lastName,proto3" json:"lastName,omitempty"`
	// unique email of the admin
	Email string `protobuf:"bytes,5,opt,name=email,proto3" json:"email,omitempty"`
	// avatar image associated to the avatar
	Avatar []byte `protobuf:"bytes,6,opt,name=avatar,proto3,oneof" json:"avatar,omitempty"`
	// notes associated to the admin
	Notes *string `protobuf:"bytes,7,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *Admin) Reset() {
	*x = Admin{}
	if protoimpl.UnsafeEnabled {
		mi := &file_admin_v1_admin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Admin) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Admin) ProtoMessage() {}

func (x *Admin) ProtoReflect() protoreflect.Message {
	mi := &file_admin_v1_admin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Admin.ProtoReflect.Descriptor instead.
func (*Admin) Descriptor() ([]byte, []int) {
	return file_admin_v1_admin_proto_rawDescGZIP(), []int{0}
}

func (x *Admin) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Admin) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}

func (x *Admin) GetFirstName() string {
	if x != nil {
		return x.FirstName
	}
	return ""
}

func (x *Admin) GetLastName() string {
	if x != nil {
		return x.LastName
	}
	return ""
}

func (x *Admin) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *Admin) GetAvatar() []byte {
	if x != nil {
		return x.Avatar
	}
	return nil
}

func (x *Admin) GetNotes() string {
	if x != nil && x.Notes != nil {
		return *x.Notes
	}
	return ""
}

var File_admin_v1_admin_proto protoreflect.FileDescriptor

var file_admin_v1_admin_proto_rawDesc = []byte{
	0x0a, 0x14, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31,
	0x22, 0xcf, 0x01, 0x0a, 0x05, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x12, 0x11, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a,
	0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x73, 0x75, 0x62, 0x12, 0x1d, 0x0a, 0x0a, 0x66, 0x69, 0x72, 0x73, 0x74, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x66, 0x69, 0x72, 0x73, 0x74, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6c, 0x61, 0x73, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x1b, 0x0a, 0x06, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x06, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x88,
	0x01, 0x01, 0x12, 0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x01, 0x52, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x09, 0x0a,
	0x07, 0x5f, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e, 0x6f, 0x74,
	0x65, 0x73, 0x42, 0x98, 0x01, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e,
	0x2e, 0x76, 0x31, 0x42, 0x0a, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0x5a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x6d,
	0x61, 0x75, 0x72, 0x79, 0x39, 0x35, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x66, 0x79, 0x2f,
	0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x73, 0x2f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x61, 0x64,
	0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x3b, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x76, 0x31, 0xa2, 0x02,
	0x03, 0x41, 0x58, 0x58, 0xaa, 0x02, 0x08, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x56, 0x31, 0xca,
	0x02, 0x08, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x14, 0x41, 0x64, 0x6d,
	0x69, 0x6e, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0xea, 0x02, 0x09, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_admin_v1_admin_proto_rawDescOnce sync.Once
	file_admin_v1_admin_proto_rawDescData = file_admin_v1_admin_proto_rawDesc
)

func file_admin_v1_admin_proto_rawDescGZIP() []byte {
	file_admin_v1_admin_proto_rawDescOnce.Do(func() {
		file_admin_v1_admin_proto_rawDescData = protoimpl.X.CompressGZIP(file_admin_v1_admin_proto_rawDescData)
	})
	return file_admin_v1_admin_proto_rawDescData
}

var file_admin_v1_admin_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_admin_v1_admin_proto_goTypes = []interface{}{
	(*Admin)(nil), // 0: admin.v1.Admin
}
var file_admin_v1_admin_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_admin_v1_admin_proto_init() }
func file_admin_v1_admin_proto_init() {
	if File_admin_v1_admin_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_admin_v1_admin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Admin); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_admin_v1_admin_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_admin_v1_admin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_admin_v1_admin_proto_goTypes,
		DependencyIndexes: file_admin_v1_admin_proto_depIdxs,
		MessageInfos:      file_admin_v1_admin_proto_msgTypes,
	}.Build()
	File_admin_v1_admin_proto = out.File
	file_admin_v1_admin_proto_rawDesc = nil
	file_admin_v1_admin_proto_goTypes = nil
	file_admin_v1_admin_proto_depIdxs = nil
}

// LoadMap populates struct fields from a map, handling decoding for special fields.
func (o *Admin) LoadMap(values map[string]interface{}) {
	if val, ok := values["_key"].(string); ok {
		o.Key = val
	}
	if val, ok := values["sub"].(string); ok {
		o.Subject = val
	}
	if val, ok := values["firstName"].(string); ok {
		o.FirstName = val
	}
	if val, ok := values["lastName"].(string); ok {
		o.LastName = val
	}
	if val, ok := values["email"].(string); ok {
		o.Email = val
	}
	if val, ok := values["avatar"].(string); ok {
		o.Avatar = utils.DecodeBytes(val)
	}
	if val, ok := values["notes"].(string); ok {
		o.Notes = &val
	}
}

// Specs ...
func (*Admin) Specs() []byte {
	var buffer bytes.Buffer
	buffer.WriteString("{")
	buffer.WriteString("\"fields\": {")
	buffer.WriteString("\"_key\": {")
	buffer.WriteString("\"name\":\"_key\",")
	buffer.WriteString("\"type\": \"string\"")
	buffer.WriteString("},")
	buffer.WriteString("\"sub\": {")
	buffer.WriteString("\"name\":\"sub\",")
	buffer.WriteString("\"type\": \"string\"")
	buffer.WriteString("},")
	buffer.WriteString("\"firstName\": {")
	buffer.WriteString("\"name\":\"firstName\",")
	buffer.WriteString("\"type\": \"string\"")
	buffer.WriteString("},")
	buffer.WriteString("\"lastName\": {")
	buffer.WriteString("\"name\":\"lastName\",")
	buffer.WriteString("\"type\": \"string\"")
	buffer.WriteString("},")
	buffer.WriteString("\"email\": {")
	buffer.WriteString("\"name\":\"email\",")
	buffer.WriteString("\"type\": \"string\"")
	buffer.WriteString("},")
	buffer.WriteString("\"avatar\": {")
	buffer.WriteString("\"name\":\"avatar\",")
	buffer.WriteString("\"optional\": true,")
	buffer.WriteString("\"type\": \"bytes\"")
	buffer.WriteString("},")
	buffer.WriteString("\"notes\": {")
	buffer.WriteString("\"name\":\"notes\",")
	buffer.WriteString("\"optional\": true,")
	buffer.WriteString("\"type\": \"string\"")
	buffer.WriteString("},")
	utils.TrimTrailingComma(&buffer)
	buffer.WriteString("},")
	buffer.WriteString("\"oneofs\": {")
	buffer.WriteString("}")
	buffer.WriteString("}")
	return buffer.Bytes()
}
