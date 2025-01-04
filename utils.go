package graphify

import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"

	"github.com/go-openapi/inflect"
	"github.com/stoewer/go-strcase"
	"golang.org/x/exp/rand"
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

// generateRandomPassword generates a random password with the following requirements:
// Password Length: 16
// Include Alpha Upper (A-Z): true
// Include Alpha Lower (a-z): true
// Include Number (0-9): true
func GenerateRandomPassword() string {
	const (
		length        = 16
		upperLetters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowerLetters  = "abcdefghijklmnopqrstuvwxyz"
		numbers       = "0123456789"
		allCharacters = upperLetters + lowerLetters + numbers
	)

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		password[i] = allCharacters[rand.Intn(len(allCharacters))]
	}

	// Ensure at least one character from each category
	password[rand.Intn(length)] = upperLetters[rand.Intn(len(upperLetters))]
	password[rand.Intn(length)] = lowerLetters[rand.Intn(len(lowerLetters))]
	password[rand.Intn(length)] = numbers[rand.Intn(len(numbers))]

	return string(password)
}

// Pure converts a value to a pure JSON value
func Pure[T any](v T) T {
	bytes, _ := json.Marshal(v)
	var result T
	json.Unmarshal(bytes, &result)
	return result
}
