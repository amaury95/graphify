package main

import (
	"context"
	"net/http"

	"github.com/amaury95/graphify"
	library "github.com/amaury95/graphify/example/domain/library/v1"
	admin "github.com/amaury95/graphify/models/domain/admin/v1"
)

func main() {
	ctx := graphify.ContextWithDatabaseConfig(context.Background(), graphify.DatabaseConfig{
		Name: "library",
	})

	common := graphify.Common{
		Connection: graphify.NewConnection(),
		Observer:   graphify.NewObserver[graphify.Topic](),
	}

	graph := graphify.NewGraph(&common)
	graph.Node(library.Book{})
	graph.Node(admin.Admin{})

	http.ListenAndServe(":8080", graph.RestHandler(ctx))
}
