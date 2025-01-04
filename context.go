package graphify

import (
	"context"

	"github.com/amaury95/graphify/pkg/dashboard/domain/account/v1"
)

/* Admin */
type adminKey struct{}

// ContextWithAdmin ...
func ContextWithAdmin(parent context.Context, admin *accountv1.Admin) context.Context {
	return context.WithValue(parent, adminKey{}, admin)
}

// AdminFromContext ...
func AdminFromContext(ctx context.Context) (value *accountv1.Admin, found bool) {
	value, found = ctx.Value(adminKey{}).(*accountv1.Admin)
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
