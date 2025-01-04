// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: account/v1/event.proto

package accountv1

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on AdminCreatedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *AdminCreatedPayload) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AdminCreatedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// AdminCreatedPayloadMultiError, or nil if none found.
func (m *AdminCreatedPayload) ValidateAll() error {
	return m.validate(true)
}

func (m *AdminCreatedPayload) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Key

	if all {
		switch v := interface{}(m.GetElement()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminCreatedPayloadValidationError{
					field:  "Element",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminCreatedPayloadValidationError{
					field:  "Element",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetElement()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminCreatedPayloadValidationError{
				field:  "Element",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetAdmin()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminCreatedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminCreatedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAdmin()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminCreatedPayloadValidationError{
				field:  "Admin",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AdminCreatedPayloadMultiError(errors)
	}

	return nil
}

// AdminCreatedPayloadMultiError is an error wrapping multiple validation
// errors returned by AdminCreatedPayload.ValidateAll() if the designated
// constraints aren't met.
type AdminCreatedPayloadMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AdminCreatedPayloadMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AdminCreatedPayloadMultiError) AllErrors() []error { return m }

// AdminCreatedPayloadValidationError is the validation error returned by
// AdminCreatedPayload.Validate if the designated constraints aren't met.
type AdminCreatedPayloadValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AdminCreatedPayloadValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AdminCreatedPayloadValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AdminCreatedPayloadValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AdminCreatedPayloadValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AdminCreatedPayloadValidationError) ErrorName() string {
	return "AdminCreatedPayloadValidationError"
}

// Error satisfies the builtin error interface
func (e AdminCreatedPayloadValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAdminCreatedPayload.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AdminCreatedPayloadValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AdminCreatedPayloadValidationError{}

// Validate checks the field values on AdminUpdatedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *AdminUpdatedPayload) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AdminUpdatedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// AdminUpdatedPayloadMultiError, or nil if none found.
func (m *AdminUpdatedPayload) ValidateAll() error {
	return m.validate(true)
}

func (m *AdminUpdatedPayload) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetElement()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminUpdatedPayloadValidationError{
					field:  "Element",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminUpdatedPayloadValidationError{
					field:  "Element",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetElement()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminUpdatedPayloadValidationError{
				field:  "Element",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetAdmin()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminUpdatedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminUpdatedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAdmin()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminUpdatedPayloadValidationError{
				field:  "Admin",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AdminUpdatedPayloadMultiError(errors)
	}

	return nil
}

// AdminUpdatedPayloadMultiError is an error wrapping multiple validation
// errors returned by AdminUpdatedPayload.ValidateAll() if the designated
// constraints aren't met.
type AdminUpdatedPayloadMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AdminUpdatedPayloadMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AdminUpdatedPayloadMultiError) AllErrors() []error { return m }

// AdminUpdatedPayloadValidationError is the validation error returned by
// AdminUpdatedPayload.Validate if the designated constraints aren't met.
type AdminUpdatedPayloadValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AdminUpdatedPayloadValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AdminUpdatedPayloadValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AdminUpdatedPayloadValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AdminUpdatedPayloadValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AdminUpdatedPayloadValidationError) ErrorName() string {
	return "AdminUpdatedPayloadValidationError"
}

// Error satisfies the builtin error interface
func (e AdminUpdatedPayloadValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAdminUpdatedPayload.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AdminUpdatedPayloadValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AdminUpdatedPayloadValidationError{}

// Validate checks the field values on AdminReplacedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *AdminReplacedPayload) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AdminReplacedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// AdminReplacedPayloadMultiError, or nil if none found.
func (m *AdminReplacedPayload) ValidateAll() error {
	return m.validate(true)
}

func (m *AdminReplacedPayload) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetElement()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminReplacedPayloadValidationError{
					field:  "Element",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminReplacedPayloadValidationError{
					field:  "Element",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetElement()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminReplacedPayloadValidationError{
				field:  "Element",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetAdmin()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminReplacedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminReplacedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAdmin()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminReplacedPayloadValidationError{
				field:  "Admin",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AdminReplacedPayloadMultiError(errors)
	}

	return nil
}

// AdminReplacedPayloadMultiError is an error wrapping multiple validation
// errors returned by AdminReplacedPayload.ValidateAll() if the designated
// constraints aren't met.
type AdminReplacedPayloadMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AdminReplacedPayloadMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AdminReplacedPayloadMultiError) AllErrors() []error { return m }

// AdminReplacedPayloadValidationError is the validation error returned by
// AdminReplacedPayload.Validate if the designated constraints aren't met.
type AdminReplacedPayloadValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AdminReplacedPayloadValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AdminReplacedPayloadValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AdminReplacedPayloadValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AdminReplacedPayloadValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AdminReplacedPayloadValidationError) ErrorName() string {
	return "AdminReplacedPayloadValidationError"
}

// Error satisfies the builtin error interface
func (e AdminReplacedPayloadValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAdminReplacedPayload.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AdminReplacedPayloadValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AdminReplacedPayloadValidationError{}

// Validate checks the field values on AdminDeletedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *AdminDeletedPayload) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AdminDeletedPayload with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// AdminDeletedPayloadMultiError, or nil if none found.
func (m *AdminDeletedPayload) ValidateAll() error {
	return m.validate(true)
}

func (m *AdminDeletedPayload) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Key

	if all {
		switch v := interface{}(m.GetAdmin()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, AdminDeletedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, AdminDeletedPayloadValidationError{
					field:  "Admin",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAdmin()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return AdminDeletedPayloadValidationError{
				field:  "Admin",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return AdminDeletedPayloadMultiError(errors)
	}

	return nil
}

// AdminDeletedPayloadMultiError is an error wrapping multiple validation
// errors returned by AdminDeletedPayload.ValidateAll() if the designated
// constraints aren't met.
type AdminDeletedPayloadMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AdminDeletedPayloadMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AdminDeletedPayloadMultiError) AllErrors() []error { return m }

// AdminDeletedPayloadValidationError is the validation error returned by
// AdminDeletedPayload.Validate if the designated constraints aren't met.
type AdminDeletedPayloadValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AdminDeletedPayloadValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AdminDeletedPayloadValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AdminDeletedPayloadValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AdminDeletedPayloadValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AdminDeletedPayloadValidationError) ErrorName() string {
	return "AdminDeletedPayloadValidationError"
}

// Error satisfies the builtin error interface
func (e AdminDeletedPayloadValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAdminDeletedPayload.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AdminDeletedPayloadValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AdminDeletedPayloadValidationError{}
