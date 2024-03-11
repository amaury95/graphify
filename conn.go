package graphify

import (
	"context"
	"fmt"
	"reflect"

	"github.com/arangodb/go-driver"
	"github.com/arangodb/go-driver/http"
)

// IConnection ...
type IConnection interface {
	// GetDatabase ...
	GetDatabase(ctx context.Context) (driver.Database, error)
	// GetCollection ...
	GetCollection(ctx context.Context, elem reflect.Type) (driver.Collection, error)
}

type connection struct {
	username, password string
}

// NewConnection ...
func NewConnection(username, password string) *connection {
	return &connection{username: username, password: password}
}

func (c *connection) GetDatabase(ctx context.Context) (db driver.Database, err error) {
	config, found := DatabaseConfigFromContext(ctx)
	if !found {
		return nil, fmt.Errorf("database config not found")
	}

	conn, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: []string{"http://localhost:8529"},
	})
	if err != nil {
		panic(err)
	}

	client, err := driver.NewClient(driver.ClientConfig{
		Connection:     conn,
		Authentication: driver.BasicAuthentication(c.username, c.password),
	})
	if err != nil {
		panic(err)
	}

	exists, err := client.DatabaseExists(ctx, config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check database existence: %w", err)
	}
	if exists {
		db, err = client.Database(ctx, config.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
	} else {
		db, err = client.CreateDatabase(ctx, config.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create database: %w", err)
		}
	}

	return db, nil
}

func (c *connection) GetCollection(ctx context.Context, elem reflect.Type) (driver.Collection, error) {
	db, err := c.GetDatabase(ctx)
	if err != nil {
		return nil, err
	}
	return db.Collection(ctx, CollectionFor(elem))
}
