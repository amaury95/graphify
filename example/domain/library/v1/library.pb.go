// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: library/v1/library.proto

package libraryv1

import (
	v1 "github.com/amaury95/graphify/pkg/models/domain/collections/v1"
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
	Country  v1.Country        `protobuf:"varint,4,opt,name=country,proto3,enum=collections.v1.Country" json:"country,omitempty"`
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

func (x *Library) GetCountry() v1.Country {
	if x != nil {
		return x.Country
	}
	return v1.Country(0)
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
	0x61, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x1a, 0x1e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xcd, 0x01, 0x0a, 0x07, 0x4c, 0x69, 0x62, 0x72, 0x61,
	0x72, 0x79, 0x12, 0x11, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x38, 0x0a, 0x08, 0x6c, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x6c, 0x69,
	0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
	0x2e, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x31, 0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x63,
	0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x1a, 0x2e, 0x0a, 0x08, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x6c, 0x61, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x02, 0x52,
	0x03, 0x6c, 0x61, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6c, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x02, 0x52, 0x03, 0x6c, 0x6e, 0x67, 0x42, 0xa9, 0x01, 0x0a, 0x0e, 0x63, 0x6f, 0x6d, 0x2e, 0x6c,
	0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x42, 0x0c, 0x4c, 0x69, 0x62, 0x72, 0x61,
	0x72, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x40, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x6d, 0x61, 0x75, 0x72, 0x79, 0x39, 0x35, 0x2f, 0x67,
	0x72, 0x61, 0x70, 0x68, 0x69, 0x66, 0x79, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x76,
	0x31, 0x3b, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x4c, 0x58,
	0x58, 0xaa, 0x02, 0x0a, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x56, 0x31, 0xca, 0x02,
	0x0a, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x16, 0x4c, 0x69,
	0x62, 0x72, 0x61, 0x72, 0x79, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0b, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x3a, 0x3a,
	0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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
	(v1.Country)(0),          // 2: collections.v1.Country
}
var file_library_v1_library_proto_depIdxs = []int32{
	1, // 0: library.v1.Library.location:type_name -> library.v1.Library.Location
	2, // 1: library.v1.Library.country:type_name -> collections.v1.Country
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
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
		"country": &graphql.ArgumentConfig{
			Type: v1.Country_Enum,
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
		"country": &graphql.Field{
			Type: v1.Country_Enum,
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
		"country": &graphql.InputObjectFieldConfig{
			Type: v1.Country_Enum,
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
		"name":  "Library",
		"@type": "type.googleapis.com/library.v1.Library",
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
			map[string]interface{}{
				"name": "country",
				"type": "enum",
				"options": map[string]interface{}{
					"0":   "COUNTRY_UNSPECIFIED",
					"1":   "COUNTRY_AFGHANISTAN",
					"2":   "COUNTRY_ALBANIA",
					"3":   "COUNTRY_ALGERIA",
					"4":   "COUNTRY_ANDORRA",
					"5":   "COUNTRY_ANGOLA",
					"6":   "COUNTRY_ANTIGUA_AND_BARBUDA",
					"7":   "COUNTRY_ARGENTINA",
					"8":   "COUNTRY_ARMENIA",
					"9":   "COUNTRY_AUSTRALIA",
					"10":  "COUNTRY_AUSTRIA",
					"11":  "COUNTRY_AZERBAIJAN",
					"12":  "COUNTRY_BAHAMAS",
					"13":  "COUNTRY_BAHRAIN",
					"14":  "COUNTRY_BANGLADESH",
					"15":  "COUNTRY_BARBADOS",
					"16":  "COUNTRY_BELARUS",
					"17":  "COUNTRY_BELGIUM",
					"18":  "COUNTRY_BELIZE",
					"19":  "COUNTRY_BENIN",
					"20":  "COUNTRY_BHUTAN",
					"21":  "COUNTRY_BOLIVIA",
					"22":  "COUNTRY_BOSNIA_AND_HERZEGOVINA",
					"23":  "COUNTRY_BOTSWANA",
					"24":  "COUNTRY_BRAZIL",
					"25":  "COUNTRY_BRUNEI",
					"26":  "COUNTRY_BULGARIA",
					"27":  "COUNTRY_BURKINA_FASO",
					"28":  "COUNTRY_BURUNDI",
					"29":  "COUNTRY_CABO_VERDE",
					"30":  "COUNTRY_CAMBODIA",
					"31":  "COUNTRY_CAMEROON",
					"32":  "COUNTRY_CANADA",
					"33":  "COUNTRY_CENTRAL_AFRICAN_REPUBLIC",
					"34":  "COUNTRY_CHAD",
					"35":  "COUNTRY_CHILE",
					"36":  "COUNTRY_CHINA",
					"37":  "COUNTRY_COLOMBIA",
					"38":  "COUNTRY_COMOROS",
					"39":  "COUNTRY_CONGO_DEMOCRATIC_REPUBLIC",
					"40":  "COUNTRY_CONGO_REPUBLIC",
					"41":  "COUNTRY_COSTA_RICA",
					"42":  "COUNTRY_COTE_DIVOIRE",
					"43":  "COUNTRY_CROATIA",
					"44":  "COUNTRY_CUBA",
					"45":  "COUNTRY_CYPRUS",
					"46":  "COUNTRY_CZECH_REPUBLIC",
					"47":  "COUNTRY_DENMARK",
					"48":  "COUNTRY_DJIBOUTI",
					"49":  "COUNTRY_DOMINICA",
					"50":  "COUNTRY_DOMINICAN_REPUBLIC",
					"51":  "COUNTRY_EAST_TIMOR",
					"52":  "COUNTRY_ECUADOR",
					"53":  "COUNTRY_EGYPT",
					"54":  "COUNTRY_EL_SALVADOR",
					"55":  "COUNTRY_EQUATORIAL_GUINEA",
					"56":  "COUNTRY_ERITREA",
					"57":  "COUNTRY_ESTONIA",
					"58":  "COUNTRY_ESWATINI",
					"59":  "COUNTRY_ETHIOPIA",
					"60":  "COUNTRY_FIJI",
					"61":  "COUNTRY_FINLAND",
					"62":  "COUNTRY_FRANCE",
					"63":  "COUNTRY_GABON",
					"64":  "COUNTRY_THE_GAMBIA",
					"65":  "COUNTRY_GEORGIA",
					"66":  "COUNTRY_GERMANY",
					"67":  "COUNTRY_GHANA",
					"68":  "COUNTRY_GREECE",
					"69":  "COUNTRY_GRENADA",
					"70":  "COUNTRY_GUATEMALA",
					"71":  "COUNTRY_GUINEA",
					"72":  "COUNTRY_GUINEA_BISSAU",
					"73":  "COUNTRY_GUYANA",
					"74":  "COUNTRY_HAITI",
					"75":  "COUNTRY_HONDURAS",
					"76":  "COUNTRY_HUNGARY",
					"77":  "COUNTRY_ICELAND",
					"78":  "COUNTRY_INDIA",
					"79":  "COUNTRY_INDONESIA",
					"80":  "COUNTRY_IRAN",
					"81":  "COUNTRY_IRAQ",
					"82":  "COUNTRY_IRELAND",
					"83":  "COUNTRY_ISRAEL",
					"84":  "COUNTRY_ITALY",
					"85":  "COUNTRY_JAMAICA",
					"86":  "COUNTRY_JAPAN",
					"87":  "COUNTRY_JORDAN",
					"88":  "COUNTRY_KAZAKHSTAN",
					"89":  "COUNTRY_KENYA",
					"90":  "COUNTRY_KIRIBATI",
					"91":  "COUNTRY_KOREA_NORTH",
					"92":  "COUNTRY_KOREA_SOUTH",
					"93":  "COUNTRY_KOSOVO",
					"94":  "COUNTRY_KUWAIT",
					"95":  "COUNTRY_KYRGYZSTAN",
					"96":  "COUNTRY_LAOS",
					"97":  "COUNTRY_LATVIA",
					"98":  "COUNTRY_LEBANON",
					"99":  "COUNTRY_LESOTHO",
					"100": "COUNTRY_LIBERIA",
					"101": "COUNTRY_LIBYA",
					"102": "COUNTRY_LIECHTENSTEIN",
					"103": "COUNTRY_LITHUANIA",
					"104": "COUNTRY_LUXEMBOURG",
					"105": "COUNTRY_MADAGASCAR",
					"106": "COUNTRY_MALAWI",
					"107": "COUNTRY_MALAYSIA",
					"108": "COUNTRY_MALDIVES",
					"109": "COUNTRY_MALI",
					"110": "COUNTRY_MALTA",
					"111": "COUNTRY_MARSHALL_ISLANDS",
					"112": "COUNTRY_MAURITANIA",
					"113": "COUNTRY_MAURITIUS",
					"114": "COUNTRY_MEXICO",
					"115": "COUNTRY_MICRONESIA_FEDERATED_STATES_OF",
					"116": "COUNTRY_MOLDOVA",
					"117": "COUNTRY_MONACO",
					"118": "COUNTRY_MONGOLIA",
					"119": "COUNTRY_MONTENEGRO",
					"120": "COUNTRY_MOROCCO",
					"121": "COUNTRY_MOZAMBIQUE",
					"122": "COUNTRY_MYANMAR_BURMA",
					"123": "COUNTRY_NAMIBIA",
					"124": "COUNTRY_NAURU",
					"125": "COUNTRY_NEPAL",
					"126": "COUNTRY_NETHERLANDS",
					"127": "COUNTRY_NEW_ZEALAND",
					"128": "COUNTRY_NICARAGUA",
					"129": "COUNTRY_NIGER",
					"130": "COUNTRY_NIGERIA",
					"131": "COUNTRY_NORTH_MACEDONIA",
					"132": "COUNTRY_NORWAY",
					"133": "COUNTRY_OMAN",
					"134": "COUNTRY_PAKISTAN",
					"135": "COUNTRY_PALAU",
					"136": "COUNTRY_PANAMA",
					"137": "COUNTRY_PAPUA_NEW_GUINEA",
					"138": "COUNTRY_PARAGUAY",
					"139": "COUNTRY_PERU",
					"140": "COUNTRY_PHILIPPINES",
					"141": "COUNTRY_POLAND",
					"142": "COUNTRY_PORTUGAL",
					"143": "COUNTRY_QATAR",
					"144": "COUNTRY_ROMANIA",
					"145": "COUNTRY_RUSSIA",
					"146": "COUNTRY_RWANDA",
					"147": "COUNTRY_SAINT_KITTS_AND_NEVIS",
					"148": "COUNTRY_SAINT_LUCIA",
					"149": "COUNTRY_SAINT_VINCENT_AND_THE_GRENADINES",
					"150": "COUNTRY_SAMOA",
					"151": "COUNTRY_SAN_MARINO",
					"152": "COUNTRY_SAO_TOME_AND_PRICIPES",
					"153": "COUNTRY_SAUDI_ARABIA",
					"154": "COUNTRY_SENEGAL",
					"155": "COUNTRY_SERBIA",
					"156": "COUNTRY_SEYCHELLES",
					"157": "COUNTRY_SIERRA_LEONE",
					"158": "COUNTRY_SINGAPORE",
					"159": "COUNTRY_SLOVAKIA",
					"160": "COUNTRY_SLOVENIA",
					"161": "COUNTRY_SOLOMON_ISLANDS",
					"162": "COUNTRY_SOMALIA",
					"163": "COUNTRY_SOUTH_AFRICA",
					"164": "COUNTRY_SPAIN",
					"165": "COUNTRY_SRI_LANKA",
					"166": "COUNTRY_SUDAN",
					"167": "COUNTRY_SUDAN_SOUTH",
					"168": "COUNTRY_SURINAME",
					"169": "COUNTRY_SWEDEN",
					"170": "COUNTRY_SWITZERLAND",
					"171": "COUNTRY_SYRIA",
					"172": "COUNTRY_TAIWAN",
					"173": "COUNTRY_TAJIKISTAN",
					"174": "COUNTRY_TANZANIA",
					"175": "COUNTRY_THAILAND",
					"176": "COUNTRY_TOGO",
					"177": "COUNTRY_TONGA",
					"178": "COUNTRY_TRINIDAD_AND_TOBAGO",
					"179": "COUNTRY_TUNISIA",
					"180": "COUNTRY_TURKEY",
					"181": "COUNTRY_TURKMENISTAN",
					"182": "COUNTRY_TUVALU",
					"183": "COUNTRY_UGANDA",
					"184": "COUNTRY_UKRAINE",
					"185": "COUNTRY_UNITED_ARAB_EMIRATES",
					"186": "COUNTRY_UNITED_KINGDOM",
					"187": "COUNTRY_UNITED_STATES",
					"188": "COUNTRY_URUGUAY",
					"189": "COUNTRY_UZBEKISTAN",
					"190": "COUNTRY_VANUATU",
					"191": "COUNTRY_VATICAN_CITY",
					"192": "COUNTRY_VENEZUELA",
					"193": "COUNTRY_VIETNAM",
					"194": "COUNTRY_YEMEN",
					"195": "COUNTRY_ZAMBIA",
					"196": "COUNTRY_ZIMBABWE",
				},
			},
		},
		"oneofs": map[string]interface{}{},
	}
}

/* Schema ... */
func (*Library_Location) Schema() map[string]interface{} {
	return map[string]interface{}{
		"name":  "Library_Location",
		"@type": "type.googleapis.com/library.v1.Library.Location",
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
	if val, ok := values["country"].(v1.Country); ok {
		o.Country = val
	}
	if val, ok := values["country"].(float64); ok {
		o.Country = v1.Country(val)
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
