package graphify

import (
	"reflect"
	"runtime"
	"strings"

	"github.com/go-openapi/inflect"
	"github.com/stoewer/go-strcase"
)

/* NODE HELPERS */

// collectionFor ...
func collectionFor(t reflect.Type) string {
	return strcase.SnakeCase(inflect.Pluralize(t.Name()))
}

func isNode(t reflect.Type) bool {
	return hasStringField(t, "Key", "_key")
}

func isEdge(t reflect.Type) bool {
	return hasStringField(t, "Key", "_key") &&
		hasStringField(t, "From", "_from") &&
		hasStringField(t, "To", "_to")
}

func hasStringField(t reflect.Type, fieldName, jsonTag string) bool {
	field, exists := t.FieldByName(fieldName)
	return exists &&
		field.Type.Kind() == reflect.String &&
		strings.Contains(field.Tag.Get("json"), jsonTag)
}

func funcName(v reflect.Value) string {
	// Get the name of the function
	name := runtime.FuncForPC(v.Pointer()).Name()
	// Trim the package path
	dotIndex := strings.LastIndex(name, ".")
	if dotIndex != -1 {
		name = name[dotIndex+1:]
	}
	dashIndex := strings.Index(name, "-")
	if dashIndex != -1 {
		name = name[:dashIndex]
	}
	return name
}
