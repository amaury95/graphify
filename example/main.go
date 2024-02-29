package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/amaury95/graphify"
	library "github.com/amaury95/graphify/example/domain/library/v1"
	admin "github.com/amaury95/graphify/models/domain/admin/v1"
	observer "github.com/amaury95/graphify/models/domain/observer/v1"
	"google.golang.org/protobuf/proto"
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

	common.Observer.Subscribe(
		graphify.CreatedTopic.With(library.Book{}), logCreatedBook)

	http.ListenAndServe(":8080", graph.RestHandler(ctx))
}

func logCreatedBook(e *graphify.Event[graphify.Topic]) error {
	payload, ok := e.Payload.(*observer.CreatedPayload)
	if !ok {
		return fmt.Errorf("payload is not CreatedPayload")
	}
	var book library.Book
	if err := proto.Unmarshal(payload.Element, &book); err != nil {
		return err
	}
	fmt.Printf("Created book: %s with key: %s", book.Title, payload.Key)
	return nil
}
