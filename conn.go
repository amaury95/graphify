package graphify

import (
	"context"
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
	database driver.Database
}

// NewConnection ...
func NewConnection(ctx context.Context, conf DatabaseConfig) *connection {
	conn, err := http.NewConnection(conf.Connection)
	if err != nil {
		panic(err)
	}

	client, err := driver.NewClient(driver.ClientConfig{
		Connection:     conn,
		Authentication: driver.BasicAuthentication(conf.UserName, conf.Password),
	})
	if err != nil {
		panic("failed to establish connection")
	}

	exists, err := client.DatabaseExists(ctx, conf.DBName)
	if err != nil {
		panic("failed to check database existence")
	}
	if exists {
		db, err := client.Database(ctx, conf.DBName)
		if err != nil {
			panic("failed to connect to database")
		}
		return &connection{database: db}
	} else {
		db, err := client.CreateDatabase(ctx, conf.DBName, nil)
		if err != nil {
			panic("failed to create database")
		}
		return &connection{database: db}
	}
}

func (c *connection) GetDatabase(ctx context.Context) (db driver.Database, err error) {
	return c.database, nil
}

func (c *connection) GetCollection(ctx context.Context, elem reflect.Type) (driver.Collection, error) {
	db, err := c.GetDatabase(ctx)
	if err != nil {
		return nil, err
	}
	return db.Collection(ctx, CollectionFor(elem))
}
