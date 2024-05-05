// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: library/v1/library.proto

package libraryv1

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

type Library struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key      string            `protobuf:"bytes,1,opt,name=_key,proto3" json:"_key,omitempty"`
	Name     string            `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Location *Library_Location `protobuf:"bytes,3,opt,name=location,proto3" json:"location,omitempty"`
}

func (x *Library) Reset() {
	*x = Library{}
	if protoimpl.UnsafeEnabled {
		mi := &file_library_v1_library_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Library) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Library) ProtoMessage() {}

func (x *Library) ProtoReflect() protoreflect.Message {
	mi := &file_library_v1_library_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Library.ProtoReflect.Descriptor instead.
func (*Library) Descriptor() ([]byte, []int) {
	return file_library_v1_library_proto_rawDescGZIP(), []int{0}
}

func (x *Library) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Library) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Library) GetLocation() *Library_Location {
	if x != nil {
		return x.Location
	}
	return nil
}

type Library_Location struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Lat float32 `protobuf:"fixed32,1,opt,name=lat,proto3" json:"lat,omitempty"`
	Lng float32 `protobuf:"fixed32,2,opt,name=lng,proto3" json:"lng,omitempty"`
}

func (x *Library_Location) Reset() {
	*x = Library_Location{}
	if protoimpl.UnsafeEnabled {
		mi := &file_library_v1_library_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Library_Location) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Library_Location) ProtoMessage() {}

func (x *Library_Location) ProtoReflect() protoreflect.Message {
	mi := &file_library_v1_library_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Library_Location.ProtoReflect.Descriptor instead.
func (*Library_Location) Descriptor() ([]byte, []int) {
	return file_library_v1_library_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Library_Location) GetLat() float32 {
	if x != nil {
		return x.Lat
	}
	return 0
}

func (x *Library_Location) GetLng() float32 {
	if x != nil {
		return x.Lng
	}
	return 0
}

var File_library_v1_library_proto protoreflect.FileDescriptor

var file_library_v1_library_proto_rawDesc = []byte{
	0x0a, 0x18, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x69, 0x62,
	0x72, 0x61, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x6c, 0x69, 0x62, 0x72,
	0x61, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x22, 0x9a, 0x01, 0x0a, 0x07, 0x4c, 0x69, 0x62, 0x72, 0x61,
	0x72, 0x79, 0x12, 0x11, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x38, 0x0a, 0x08, 0x6c, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x6c, 0x69,
	0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
	0x2e, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x1a, 0x2e, 0x0a, 0x08, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x10, 0x0a, 0x03, 0x6c, 0x61, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x02, 0x52, 0x03, 0x6c, 0x61,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x6c, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x02, 0x52, 0x03,
	0x6c, 0x6e, 0x67, 0x42, 0xa9, 0x01, 0x0a, 0x0e, 0x63, 0x6f, 0x6d, 0x2e, 0x6c, 0x69, 0x62, 0x72,
	0x61, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x42, 0x0c, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x40, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x61, 0x6d, 0x61, 0x75, 0x72, 0x79, 0x39, 0x35, 0x2f, 0x67, 0x72, 0x61, 0x70,
	0x68, 0x69, 0x66, 0x79, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x2f, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x76, 0x31, 0x3b, 0x6c,
	0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x4c, 0x58, 0x58, 0xaa, 0x02,
	0x0a, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x0a, 0x4c, 0x69,
	0x62, 0x72, 0x61, 0x72, 0x79, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x16, 0x4c, 0x69, 0x62, 0x72, 0x61,
	0x72, 0x79, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0xea, 0x02, 0x0b, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x3a, 0x3a, 0x56, 0x31, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_library_v1_library_proto_rawDescOnce sync.Once
	file_library_v1_library_proto_rawDescData = file_library_v1_library_proto_rawDesc
)

func file_library_v1_library_proto_rawDescGZIP() []byte {
	file_library_v1_library_proto_rawDescOnce.Do(func() {
		file_library_v1_library_proto_rawDescData = protoimpl.X.CompressGZIP(file_library_v1_library_proto_rawDescData)
	})
	return file_library_v1_library_proto_rawDescData
}

var file_library_v1_library_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_library_v1_library_proto_goTypes = []interface{}{
	(*Library)(nil),          // 0: library.v1.Library
	(*Library_Location)(nil), // 1: library.v1.Library.Location
}
var file_library_v1_library_proto_depIdxs = []int32{
	1, // 0: library.v1.Library.location:type_name -> library.v1.Library.Location
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_library_v1_library_proto_init() }
func file_library_v1_library_proto_init() {
	if File_library_v1_library_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_library_v1_library_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Library); i {
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
		file_library_v1_library_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Library_Location); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_library_v1_library_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_library_v1_library_proto_goTypes,
		DependencyIndexes: file_library_v1_library_proto_depIdxs,
		MessageInfos:      file_library_v1_library_proto_msgTypes,
	}.Build()
	File_library_v1_library_proto = out.File
	file_library_v1_library_proto_rawDesc = nil
	file_library_v1_library_proto_goTypes = nil
	file_library_v1_library_proto_depIdxs = nil
}

/*
	Graphql object
*/

/* Argument ... */
func (*Library) Argument() graphql.FieldConfigArgument {
	return graphql.FieldConfigArgument{
		"_key": &graphql.ArgumentConfig{
			Type: graphql.ID,
		},
		"name": &graphql.ArgumentConfig{
			Type: graphql.String,
		},
		"location": &graphql.ArgumentConfig{
			Type: Library_Location_Input,
		},
	}
}

/* Output ... */
func (*Library) Output() graphql.Output {
	return Library_Object
}

/* Object ... */
func (*Library) Object() *graphql.Object {
	return Library_Object
}

var Library_Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Library",
	Fields: graphql.Fields{
		"_key": &graphql.Field{
			Type: graphql.ID,
		},
		"name": &graphql.Field{
			Type: graphql.String,
		},
		"location": &graphql.Field{
			Type: Library_Location_Object,
		},
	},
	Description: "",
})

var Library_Input = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "Library_Input",
	Fields: graphql.InputObjectConfigFieldMap{
		"_key": &graphql.InputObjectFieldConfig{
			Type: graphql.ID,
		},
		"name": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"location": &graphql.InputObjectFieldConfig{
			Type: Library_Location_Input,
		},
	},
})

/* Argument ... */
func (*Library_Location) Argument() graphql.FieldConfigArgument {
	return graphql.FieldConfigArgument{
		"lat": &graphql.ArgumentConfig{
			Type: graphql.Float,
		},
		"lng": &graphql.ArgumentConfig{
			Type: graphql.Float,
		},
	}
}

/* Output ... */
func (*Library_Location) Output() graphql.Output {
	return Library_Location_Object
}

/* Object ... */
func (*Library_Location) Object() *graphql.Object {
	return Library_Location_Object
}

var Library_Location_Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Library_Location",
	Fields: graphql.Fields{
		"lat": &graphql.Field{
			Type: graphql.Float,
		},
		"lng": &graphql.Field{
			Type: graphql.Float,
		},
	},
	Description: "",
})

var Library_Location_Input = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "Library_Location_Input",
	Fields: graphql.InputObjectConfigFieldMap{
		"lat": &graphql.InputObjectFieldConfig{
			Type: graphql.Float,
		},
		"lng": &graphql.InputObjectFieldConfig{
			Type: graphql.Float,
		},
	},
})

/*
	Graphify schema module
*/

/* Schema ... */
func (*Library) Schema() map[string]interface{} {
	return map[string]interface{}{
		"name": "Library",
		"fields": []interface{}{
			map[string]interface{}{
				"name": "_key",
				"type": "string",
			},
			map[string]interface{}{
				"name": "name",
				"type": "string",
			},
			map[string]interface{}{
				"name":     "location",
				"optional": true,
				"type":     "message",
				"schema":   new(Library_Location).Schema(),
			},
		},
		"oneofs": map[string]interface{}{},
	}
}

/* Schema ... */
func (*Library_Location) Schema() map[string]interface{} {
	return map[string]interface{}{
		"name": "Library_Location",
		"fields": []interface{}{
			map[string]interface{}{
				"name": "lat",
				"type": "float",
			},
			map[string]interface{}{
				"name": "lng",
				"type": "float",
			},
		},
		"oneofs": map[string]interface{}{},
	}
}

/*
	Graphify unmarshaler
*/

/* UnmarshalJSON ...*/
func (o *Library) UnmarshalJSON(b []byte) error {
	if values, err := utils.MapFromBytes(b); err != nil {
		return err
	} else {
		o.UnmarshalMap(values)
	}
	return nil
}

/* UnmarshalMap populates struct fields from a map, handling decoding for special fields. */
func (o *Library) UnmarshalMap(values map[string]interface{}) {
	if val, ok := values["_key"].(string); ok {
		o.Key = val
	}
	if val, ok := values["name"].(string); ok {
		o.Name = val
	}
	if val, ok := values["location"].(map[string]interface{}); ok {
		field := new(Library_Location)
		field.UnmarshalMap(val)
		o.Location = field
	}
}

/* UnmarshalJSON ...*/
func (o *Library_Location) UnmarshalJSON(b []byte) error {
	if values, err := utils.MapFromBytes(b); err != nil {
		return err
	} else {
		o.UnmarshalMap(values)
	}
	return nil
}

/* UnmarshalMap populates struct fields from a map, handling decoding for special fields. */
func (o *Library_Location) UnmarshalMap(values map[string]interface{}) {
	if val, ok := values["lat"].(float64); ok {
		o.Lat = float32(val)
	}
	if val, ok := values["lng"].(float64); ok {
		o.Lng = float32(val)
	}
}
