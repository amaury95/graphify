package graphify

import (
	"context"

	adminv1 "github.com/amaury95/graphify/models/domain/admin/v1"
)

// DATABASE CONFIG
type dbConfKey struct{}

// ContextWithDatabaseConfig ...
func ContextWithDatabaseConfig(ctx context.Context, cnf *DatabaseConfig) context.Context {
	return context.WithValue(ctx, dbConfKey{}, cnf)
}

// DatabaseConfigFromContext ...
func DatabaseConfigFromContext(ctx context.Context) (config *DatabaseConfig, found bool) {
	val := ctx.Value(dbConfKey{})
	result, ok := val.(*DatabaseConfig)
	if !ok {
		return nil, false
	}
	return result, true
}

// ADMIN
type adminKey struct{}

// ContextWithAdmin ...
func ContextWithAdmin(ctx context.Context, admin *adminv1.Admin) context.Context {
	return context.WithValue(ctx, adminKey{}, admin)
}

// AdminFromContext ...
func AdminFromContext(ctx context.Context) (admin *adminv1.Admin, found bool) {
	val := ctx.Value(adminKey{})
	result, ok := val.(*adminv1.Admin)
	if !ok {
		return nil, false
	}
	return result, true
}
