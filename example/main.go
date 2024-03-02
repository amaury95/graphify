package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/term"

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
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
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
		Storage:    graphify.NewFilesystemStorage("./uploads", 10<<20), // 10 MB limit
	}

	graph := graphify.NewGraph(&common)
	graph.Node(admin.Admin_Account{})

	graph.Node(library.Book{})
	graph.Node(library.Client{})
	graph.Edge(library.Client{}, library.Book{}, library.Borrow{})

	common.Observer.Subscribe(
		graphify.CreatedTopic.For(library.Book{}), logCreatedBook)

	fmt.Println("\nStarting server at port :8080")
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
