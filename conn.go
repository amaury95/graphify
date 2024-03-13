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
	conf DatabaseConfig
}

// NewConnection ...
func NewConnection(conf DatabaseConfig) *connection {
	return &connection{conf}
}

func (c *connection) GetDatabase(ctx context.Context) (db driver.Database, err error) {
	conn, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: []string{"http://localhost:8529"},
	})
	if err != nil {
		panic(err)
	}

	client, err := driver.NewClient(driver.ClientConfig{
		Connection:     conn,
		Authentication: driver.BasicAuthentication(c.conf.UserName, c.conf.Password),
	})
	if err != nil {
		panic(err)
	}

	exists, err := client.DatabaseExists(ctx, c.conf.DBName)
	if err != nil {
		return nil, fmt.Errorf("failed to check database existence: %w", err)
	}
	if exists {
		db, err = client.Database(ctx, c.conf.DBName)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
	} else {
		db, err = client.CreateDatabase(ctx, c.conf.DBName, nil)
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
