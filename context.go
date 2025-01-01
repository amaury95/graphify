package graphify

import (
	"context"

	adminv1 "github.com/amaury95/graphify/pkg/models/domain/admin/v1"
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
