// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: relation/v1/library.proto

package relationv1

import (
	utils "github.com/amaury95/protoc-gen-graphify/utils"
	graphql "github.com/graphql-go/graphql"
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

type Borrow struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key  string `protobuf:"bytes,1,opt,name=_key,proto3" json:"_key,omitempty"`
	From string `protobuf:"bytes,2,opt,name=_from,proto3" json:"_from,omitempty"`
	To   string `protobuf:"bytes,3,opt,name=_to,proto3" json:"_to,omitempty"`
	Date *int64 `protobuf:"varint,4,opt,name=date,proto3,oneof" json:"date,omitempty"`
}

func (x *Borrow) Reset() {
	*x = Borrow{}
	if protoimpl.UnsafeEnabled {
		mi := &file_relation_v1_library_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Borrow) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Borrow) ProtoMessage() {}

func (x *Borrow) ProtoReflect() protoreflect.Message {
	mi := &file_relation_v1_library_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Borrow.ProtoReflect.Descriptor instead.
func (*Borrow) Descriptor() ([]byte, []int) {
	return file_relation_v1_library_proto_rawDescGZIP(), []int{0}
}

func (x *Borrow) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Borrow) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *Borrow) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *Borrow) GetDate() int64 {
	if x != nil && x.Date != nil {
		return *x.Date
	}
	return 0
}

var File_relation_v1_library_proto protoreflect.FileDescriptor

var file_relation_v1_library_proto_rawDesc = []byte{
	0x0a, 0x19, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x69,
	0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x72, 0x65, 0x6c,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x22, 0x63, 0x0a, 0x06, 0x42, 0x6f, 0x72, 0x72,
	0x6f, 0x77, 0x12, 0x11, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x13, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0f, 0x0a, 0x02, 0x74, 0x6f,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x5f, 0x74, 0x6f, 0x12, 0x17, 0x0a, 0x04, 0x64,
	0x61, 0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x48, 0x00, 0x52, 0x04, 0x64, 0x61, 0x74,
	0x65, 0x88, 0x01, 0x01, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x64, 0x61, 0x74, 0x65, 0x42, 0xb0, 0x01,
	0x0a, 0x0f, 0x63, 0x6f, 0x6d, 0x2e, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x42, 0x0c, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x6d,
	0x61, 0x75, 0x72, 0x79, 0x39, 0x35, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x66, 0x79, 0x2f,
	0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x72,
	0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x3b, 0x72, 0x65, 0x6c, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x52, 0x58, 0x58, 0xaa, 0x02, 0x0b, 0x52, 0x65,
	0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x0b, 0x52, 0x65, 0x6c, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x17, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0xea, 0x02, 0x0c, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x3a, 0x56, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_relation_v1_library_proto_rawDescOnce sync.Once
	file_relation_v1_library_proto_rawDescData = file_relation_v1_library_proto_rawDesc
)

func file_relation_v1_library_proto_rawDescGZIP() []byte {
	file_relation_v1_library_proto_rawDescOnce.Do(func() {
		file_relation_v1_library_proto_rawDescData = protoimpl.X.CompressGZIP(file_relation_v1_library_proto_rawDescData)
	})
	return file_relation_v1_library_proto_rawDescData
}

var file_relation_v1_library_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_relation_v1_library_proto_goTypes = []interface{}{
	(*Borrow)(nil), // 0: relation.v1.Borrow
}
var file_relation_v1_library_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_relation_v1_library_proto_init() }
func file_relation_v1_library_proto_init() {
	if File_relation_v1_library_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_relation_v1_library_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Borrow); i {
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
	file_relation_v1_library_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_relation_v1_library_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_relation_v1_library_proto_goTypes,
		DependencyIndexes: file_relation_v1_library_proto_depIdxs,
		MessageInfos:      file_relation_v1_library_proto_msgTypes,
	}.Build()
	File_relation_v1_library_proto = out.File
	file_relation_v1_library_proto_rawDesc = nil
	file_relation_v1_library_proto_goTypes = nil
	file_relation_v1_library_proto_depIdxs = nil
}

/*
	Graphql object
*/

/* Argument ... */
func (*Borrow) Argument() graphql.FieldConfigArgument {
	return graphql.FieldConfigArgument{
		"_key": &graphql.ArgumentConfig{
			Type: graphql.ID,
		},
		"_from": &graphql.ArgumentConfig{
			Type: graphql.String,
		},
		"_to": &graphql.ArgumentConfig{
			Type: graphql.String,
		},
		"date": &graphql.ArgumentConfig{
			Type: graphql.Int,
		},
	}
}

/* Output ... */
func (*Borrow) Output() graphql.Output {
	return Borrow_Object
}

/* Object ... */
func (*Borrow) Object() *graphql.Object {
	return Borrow_Object
}

var Borrow_Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Borrow",
	Fields: graphql.Fields{
		"_key": &graphql.Field{
			Type: graphql.ID,
		},
		"_from": &graphql.Field{
			Type: graphql.String,
		},
		"_to": &graphql.Field{
			Type: graphql.String,
		},
		"date": &graphql.Field{
			Type: graphql.Int,
		},
	},
	Description: "",
})

var option_Borrow_Date = graphql.NewObject(graphql.ObjectConfig{
	Name: "Borrow_Date",
	Fields: graphql.Fields{
		"Date": &graphql.Field{
			Type: graphql.Int,
		},
	},
})

var Borrow_Input = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "Borrow_Input",
	Fields: graphql.InputObjectConfigFieldMap{
		"_key": &graphql.InputObjectFieldConfig{
			Type: graphql.ID,
		},
		"_from": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"_to": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"date": &graphql.InputObjectFieldConfig{
			Type: graphql.Int,
		},
	},
})

/*
	Graphify schema module
*/

/* Schema ... */
func (*Borrow) Schema() map[string]interface{} {
	return map[string]interface{}{
		"name": "Borrow",
		"fields": []interface{}{
			map[string]interface{}{
				"name": "_key",
				"type": "string",
			},
			map[string]interface{}{
				"name": "_from",
				"type": "string",
			},
			map[string]interface{}{
				"name": "_to",
				"type": "string",
			},
			map[string]interface{}{
				"name":     "date",
				"optional": true,
				"type":     "int64",
			},
		},
		"oneofs": map[string]interface{}{},
	}
}

/*
	Graphify unmarshaler
*/

/* UnmarshalJSON ...*/
func (o *Borrow) UnmarshalJSON(b []byte) error {
	if values, err := utils.MapFromBytes(b); err != nil {
		return err
	} else {
		o.UnmarshalMap(values)
	}
	return nil
}

/* UnmarshalMap populates struct fields from a map, handling decoding for special fields. */
func (o *Borrow) UnmarshalMap(values map[string]interface{}) {
	if val, ok := values["_key"].(string); ok {
		o.Key = val
	}
	if val, ok := values["_from"].(string); ok {
		o.From = val
	}
	if val, ok := values["_to"].(string); ok {
		o.To = val
	}
	if val, ok := values["date"].(float64); ok {
		tmp := int64(val)
		o.Date = &tmp
	}
}
