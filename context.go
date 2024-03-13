package graphify

import (
	"context"

	adminv1 "github.com/amaury95/graphify/models/domain/admin/v1"
)

// Admin
type adminKey struct{}

// ContextWithAdmin ...
func ContextWithAdmin(parent context.Context, admin *adminv1.Admin) context.Context {
	return context.WithValue(parent, adminKey{}, admin)
}

// AdminFromContext ...
func AdminFromContext(ctx context.Context) (admin *adminv1.Admin, found bool) {
	val := ctx.Value(adminKey{})
	if result, ok := val.(*adminv1.Admin); ok {
		return result, true
	}
	return nil, false
}

// IConnection
type connectionKey struct{}

// ContextWithConnection ...
func ContextWithConnection(parent context.Context, conn IConnection) context.Context {
	return context.WithValue(parent, connectionKey{}, conn)
}

// ConnectionFromContext ...
func ConnectionFromContext(ctx context.Context) (conn IConnection, found bool) {
	val := ctx.Value(connectionKey{})
	if result, ok := val.(IConnection); ok {
		return result, true
	}
	return nil, false
}

// IObserver
type observerKey struct{}

// ContextWithObserver ...
func ContextWithObserver(parent context.Context, observer IObserver[Topic]) context.Context {
	return context.WithValue(parent, observerKey{}, observer)
}

// ObserverFromContext ...
func ObserverFromContext(ctx context.Context) (observer IObserver[Topic], found bool) {
	val := ctx.Value(observerKey{})
	if result, ok := val.(IObserver[Topic]); ok {
		return result, true
	}
	return nil, false
}

// IStorage
type storageKey struct{}

func ContextWithStorage(parent context.Context, storage IFileStorage) context.Context {
	return context.WithValue(parent, storageKey{}, storage)
}

func StorageFromContext(ctx context.Context) (storage IFileStorage, found bool) {
	val := ctx.Value(storageKey{})
	if result, ok := val.(IFileStorage); ok {
		return result, true
	}
	return nil, false
}
