package graphify

import "strings"

// IVars ...
type IVars interface {
	// Limit ...
	Limit() string

	// Filters ...
	Filters() string

	// Values ...
	Values() map[string]interface{}
}

// bindVars ...
type bindVars struct {
	values map[string]interface{}
}

// Filter ...
func Filter(keyValues ...interface{}) *bindVars {
	if len(keyValues)%2 != 0 {
		panic("keyValues must be a list of key-value pairs")
	}
	v := new(bindVars)
	v.values = make(map[string]interface{}, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		if key, ok := keyValues[i].(string); ok {
			v.values[key] = keyValues[i+1]
		}
	}
	return v
}

func (v *bindVars) Values() map[string]interface{} {
	return v.values
}

func (v *bindVars) init() {
	if v.values == nil {
		v.values = make(map[string]interface{})
	}
}

func (v *bindVars) Limit() string {
	v.init()
	_, hasOffset := v.values["offset"]
	_, hasCount := v.values["count"]
	if hasOffset && hasCount {
		return "LIMIT @offset, @count"
	}
	if hasCount {
		return "LIMIT @count"
	}
	return ""
}

func (v *bindVars) Filters() string {
	v.init()
	var filters []string
	for key := range v.values {
		if ignoreKey.Ignore(key) {
			continue
		}
		if strings.Contains(key, ".") {
			filters = append(filters, key+" == @"+removeUntilFirstDot(key))
		} else {
			filters = append(filters, "doc."+key+" == @"+key)
		}
	}
	if len(filters) > 0 {
		return "FILTER " + strings.Join(filters, " && ")
	}
	return ""
}

func (v *bindVars) From(args map[string]interface{}) *bindVars {
	v.init()
	for key, value := range args {
		v.values[key] = value
	}
	return v
}

func (v *bindVars) WithLimit(count, offset int64) *bindVars {
	v.init()
	v.values["count"] = count
	v.values["offset"] = offset
	return v
}

func (v *bindVars) WithCount(count int64) *bindVars {
	v.init()
	v.values["count"] = count
	return v
}

func (v *bindVars) WithOffset(offset int64) *bindVars {
	v.init()
	v.values["offset"] = offset
	return v
}

func (v *bindVars) WithFilter(key string, value interface{}) *bindVars {
	v.init()
	v.values[key] = value
	return v
}

// ignoreCollection ...
type ignoreCollection []func(string) bool

// Ignore ...
func (col *ignoreCollection) Ignore(key string) bool {
	for _, ignore := range *col {
		if ignore(key) {
			return true
		}
	}
	return false
}

// ignoreKey ...
var ignoreKey ignoreCollection = []func(string) bool{
	func(key string) bool { return key[0] == '@' },                     // prefix
	func(key string) bool { return len(key) == 0 },                     // unset
	func(key string) bool { return key == "count" || key == "offset" }, // limit
}

// removeUntilFirstDot ...
func removeUntilFirstDot(s string) string {
	index := strings.Index(s, ".")
	if index == -1 {
		return s // Return the original string if there's no dot
	}
	return s[index+1:]
}
