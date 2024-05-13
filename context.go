package graphify

import (
	"context"

	adminv1 "github.com/amaury95/graphify/models/domain/admin/v1"
)

/* Admin */
type adminKey struct{}

// ContextWithAdmin ...
func ContextWithAdmin(parent context.Context, admin *adminv1.Admin) context.Context {
	return context.WithValue(parent, adminKey{}, admin)
}

// AdminFromContext ...
func AdminFromContext(ctx context.Context) (value *adminv1.Admin, found bool) {
	value, found = ctx.Value(adminKey{}).(*adminv1.Admin)
	return
}

/* IConnection */
type connectionKey struct{}

// ContextWithConnection ...
func ContextWithConnection(parent context.Context, conn IConnection) context.Context {
	return context.WithValue(parent, connectionKey{}, conn)
}

// ConnectionFromContext ...
func ConnectionFromContext(ctx context.Context) (value IConnection, found bool) {
	value, found = ctx.Value(connectionKey{}).(IConnection)
	return
}

/* IObserver */
type observerKey struct{}

// ContextWithObserver ...
func ContextWithObserver(parent context.Context, observer IObserver[Topic]) context.Context {
	return context.WithValue(parent, observerKey{}, observer)
}

// ObserverFromContext ...
func ObserverFromContext(ctx context.Context) (value IObserver[Topic], found bool) {
	value, found = ctx.Value(observerKey{}).(IObserver[Topic])
	return
}

/* IStorage */
type storageKey struct{}

func ContextWithStorage(parent context.Context, storage IFileStorage) context.Context {
	return context.WithValue(parent, storageKey{}, storage)
}

func StorageFromContext(ctx context.Context) (value IFileStorage, found bool) {
	value, found = ctx.Value(storageKey{}).(IFileStorage)
	return
}

/* Development Environment (Set if env is in development, otherwise assumes production) */
type developmentKey struct{}

// DevelopmentContext ...
func DevelopmentContext(parent context.Context) context.Context {
	return context.WithValue(parent, developmentKey{}, true)
}

// IsDevelopmentContext ...
func IsDevelopmentContext(ctx context.Context) (value bool) {
	value = ctx.Value(developmentKey{}).(bool)
	return
}

/* Secret Key */
type secretKey struct{}

func ContextWithSecret(parent context.Context, secret []byte) context.Context {
	return context.WithValue(parent, secretKey{}, secret)
}

func SecretFromContext(ctx context.Context) (value []byte, found bool) {
	value, found = ctx.Value(secretKey{}).([]byte)
	return
}
