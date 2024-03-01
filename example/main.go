package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/amaury95/graphify"
	library "github.com/amaury95/graphify/example/domain/library/v1"
	admin "github.com/amaury95/graphify/models/domain/admin/v1"
	observer "github.com/amaury95/graphify/models/domain/observer/v1"
	"google.golang.org/protobuf/proto"
)

func main() {
	// Prompt for username
	fmt.Print("Enter ArangoDB username: ")
	var username string
	fmt.Scanln(&username)

	// Prompt for password
	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	ctx := graphify.ContextWithDatabaseConfig(context.Background(), graphify.DatabaseConfig{
		Name: "library",
	})

	common := graphify.Common{
		Connection: graphify.NewConnection(username, string(password)),
		Observer:   graphify.NewObserver[graphify.Topic](),
	}

	graph := graphify.NewGraph(&common)
	graph.Node(library.Book{})
	graph.Node(admin.Admin{})

	common.Observer.Subscribe(
		graphify.CreatedTopic.For(library.Book{}), logCreatedBook)

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
