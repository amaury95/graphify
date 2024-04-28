package graphify

import (
	"reflect"
	"sync"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// IObserver ...
type IObserver[T comparable] interface {
	// Subscribe ...
	Subscribe(t T, p Processor[T]) SourceID
	// Unsubscribe ...
	Unsubscribe(s SourceID)
	// Emit ...
	Emit(e *Event[T]) error
}

// SourceID ...
type SourceID int64

// Event ...
type Event[T comparable] struct {
	// Topic ...
	Topic T
	// Payload ...
	Payload protoreflect.ProtoMessage
	// Timestamp ...
	Timestamp time.Time
}

// Processor ...
type Processor[T comparable] func(e *Event[T]) error

type processorRow[T comparable] struct {
	id        SourceID
	processor Processor[T]
}

// Observer ...
type Observer[T comparable] struct {
	subscribers map[T][]*processorRow[T]
	sources     map[SourceID]T
	counter     SourceID
	m           sync.RWMutex
}

// Subscribe ...
func (o *Observer[T]) Subscribe(t T, p Processor[T]) SourceID {
	o.m.Lock()
	counter := o.counter + 1
	o.counter = counter
	o.subscribers[t] = append(o.subscribers[t], &processorRow[T]{
		id:        o.counter,
		processor: p,
	})
	o.sources[counter] = t
	o.m.Unlock()
	return counter
}

// Unsubscribe ...
func (o *Observer[T]) Unsubscribe(s SourceID) {
	o.m.Lock()
	t, ok := o.sources[s]
	if !ok {
		o.m.Unlock()
		return
	}
	delete(o.sources, s)
	res := make([]*processorRow[T], 0, len(o.subscribers[t]))
	for _, row := range o.subscribers[t] {
		if row.id != s {
			res = append(res, row)
		}
	}
	o.subscribers[t] = res
	o.m.Unlock()
}

// Emit ...
func (o *Observer[T]) Emit(e *Event[T]) error {
	o.m.RLock()
	for _, row := range o.subscribers[e.Topic] {
		err := row.processor(e)
		if err != nil {
			o.m.RUnlock()
			return err
		}
	}
	o.m.RUnlock()
	return nil
}

// NewObserver ...
func NewObserver[T comparable]() *Observer[T] {
	return &Observer[T]{
		subscribers: make(map[T][]*processorRow[T]),
		sources:     make(map[SourceID]T),
		counter:     0,
		m:           sync.RWMutex{},
	}
}

/* OPERATION TOPICS */

type Topic string

func (t Topic) For(elem any) Topic {
	return Topic(string(t) + "_" + CollectionFor(reflect.TypeOf(elem)))
}

var (
	CreatedTopic Topic = "created"
	UpdatedTopic Topic = "updated"
	ReplacedTopic Topic = "replaced"
	DeletedTopic Topic = "deleted"
)

var (
	AdminCreatedTopic Topic = "admin_created"
	AdminUpdatedTopic Topic = "admin_updated"
	AdminReplacedTopic Topic = "admin_replaced"
	AdminDeletedTopic Topic = "admin_deleted"
)
