package graphify

import (
	"context"
	"fmt"
)

// DATABASE CONFIG
type dbConfKey struct{}

// ContextWithDatabaseConfig ...
func ContextWithDatabaseConfig(ctx context.Context, cnf DatabaseConfig) context.Context {
	return context.WithValue(ctx, dbConfKey{}, cnf)
}

// DatabaseConfigFromContext ...
func DatabaseConfigFromContext(ctx context.Context) (*DatabaseConfig, error) {
	val := ctx.Value(dbConfKey{})
	cnf, ok := val.(DatabaseConfig)
	if !ok {
		return nil, fmt.Errorf("database config not present in context")
	}
	return &cnf, nil
}
