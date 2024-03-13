package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	// "os"
	// "golang.org/x/term"

	"github.com/amaury95/graphify"
	library "github.com/amaury95/graphify/example/domain/library/v1"
	admin "github.com/amaury95/graphify/models/domain/admin/v1"
	observer "github.com/amaury95/graphify/models/domain/observer/v1"
	"github.com/gorilla/mux"
	"golang.org/x/term"
	"google.golang.org/protobuf/proto"
)

func main() {
	var (
		username string
		password []byte
		err      error
	)
	// Prompt for username
	fmt.Print("Enter ArangoDB username: ")
	fmt.Scanln(&username)

	// Prompt for password
	fmt.Print("Enter password: ")
	password, err = term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	// define app context
	ctx := context.Background()

	// Add config to context
	ctx = graphify.ContextWithConnection(ctx,
		graphify.NewConnection(
			graphify.DatabaseConfig{DBName: "library", UserName: username, Password: string(password)}))

	ctx = graphify.ContextWithObserver(ctx,
		graphify.NewObserver[graphify.Topic]())

	ctx = graphify.ContextWithStorage(ctx,
		graphify.NewFilesystemStorage("./uploads", 10<<20)) // 10 MB limit

	// Create graph
	graph := graphify.NewGraph()

	// Add graph definitions
	graph.Node(admin.Admin{})
	graph.Node(library.Book{})
	graph.Node(library.Client{})
	graph.Edge(library.Client{}, library.Book{}, library.Borrow{})

	if observer, found := graphify.ObserverFromContext(ctx); found {
		observer.Subscribe(
			graphify.CreatedTopic.For(library.Book{}), logCreatedBook)
	}

	// Create a new router
	router := mux.NewRouter()

	// Define routes using PathPrefix to match URL prefixes
	router.PathPrefix("/admin").Handler(
		graph.RestHandler(ctx))

	router.PathPrefix("/graphql").Handler(
		graph.GraphQLHandler(ctx))

	// Create a server with the given multiplexer
	server := &http.Server{
		Addr:        ":8080",
		Handler:     router,
		BaseContext: func(net.Listener) context.Context { return ctx }, // inject context with config
	}

	// Serve handlers
	fmt.Println("\nServer is listening on :8080")
	if err = server.ListenAndServe(); err != nil {
		fmt.Println("Error:", err)
	}
}

// logCreatedBook ...
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
