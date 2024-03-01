package graphify

import (
	"reflect"
	"strings"

	"github.com/go-openapi/inflect"
	"github.com/stoewer/go-strcase"
)

/* NODE HELPERS */

// CollectionFor ...
func CollectionFor(t reflect.Type) string {
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

/* OPERATION TOPICS */

type Topic string

func (t Topic) For(elem interface{}) Topic {
	return Topic(string(t) + "_" + CollectionFor(reflect.TypeOf(elem)))
}

var (
	CreatedTopic Topic = "created"
	UpdatedTopic Topic = "updated"
	DeletedTopic Topic = "deleted"
)
