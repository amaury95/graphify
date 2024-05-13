package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/amaury95/graphify"
	"github.com/amaury95/graphify/example/domain/library/v1"
	"github.com/amaury95/graphify/example/domain/relation/v1"
	"github.com/amaury95/graphify/models/domain/observer/v1"
	"github.com/arangodb/go-driver"
	config "github.com/arangodb/go-driver/http"
	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"
)

func main() {
	// Define app context
	ctx := graphify.DevelopmentContext(context.Background())

	// Configure app context
	ctx = graphify.ContextWithConnection(ctx,
		graphify.NewConnection(ctx,
			graphify.DatabaseConfig{
				DBName:     "library",
				UserName:   "library",
				Password:   "0Jt8Vsyp",
				Connection: config.ConnectionConfig{Endpoints: []string{"http://localhost:8529"}},
			},
		))

	ctx = graphify.ContextWithSecret(ctx,
		[]byte("secret"))

	ctx = graphify.ContextWithObserver(ctx,
		graphify.NewObserver[graphify.Topic]())

	ctx = graphify.ContextWithStorage(ctx,
		graphify.NewFilesystemStorage("./uploads", 10<<20)) // 10 MB limit

	// Create and define graph
	graph := graphify.NewGraph()

	graph.Node(libraryv1.Book{})
	graph.Node(libraryv1.Client{})
	graph.Node(libraryv1.Library{})
	graph.Edge(libraryv1.Client{}, libraryv1.Book{}, relationv1.Borrow{})

	graphify.Collection(ctx, libraryv1.Library{}, func(ctx context.Context, c driver.Collection) {
		c.EnsureGeoIndex(ctx, []string{"location"}, &driver.EnsureGeoIndexOptions{})
	})
	graph.AutoMigrate(ctx)

	// Add observer events
	if observer, found := graphify.ObserverFromContext(ctx); found {
		observer.Subscribe(
			graphify.CreatedTopic.For(libraryv1.Book{}), logCreatedBook)
	}

	// Create and define routes
	router := mux.NewRouter()

	// Define routes using PathPrefix to match URL prefixes
	router.PathPrefix("/admin").Handler(
		graph.RestHandler(ctx))

	router.PathPrefix("/graphql").Handler(
		graph.GraphQLHandler(ctx,
			graph.WithUnsafeHandlers(),
			graph.Query(fitzgeraldBooks),
			graph.Mutation(createBook),
		))

	// Create a server with the given multiplexer
	server := &http.Server{
		Addr:        ":8080",
		Handler:     router,
		BaseContext: func(net.Listener) context.Context { return ctx }, // Inject app context to requests
	}

	// Serve handlers
	fmt.Println("\nServer is listening on :8080")
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("Error:", err)
	}
}

// logCreatedBook ...
func logCreatedBook(e *graphify.Event[graphify.Topic]) error {
	payload, ok := e.Payload.(*observerv1.CreatedPayload)
	if !ok {
		return fmt.Errorf("payload is not CreatedPayload")
	}
	var book libraryv1.Book
	if err := proto.Unmarshal(payload.Element, &book); err != nil {
		return err
	}
	fmt.Printf("Created book: %s with key: %s", book.Title, payload.Key)
	return nil
}

// fitzgeraldBooks is an example of query without arguments
func fitzgeraldBooks(ctx context.Context) (resp *libraryv1.ListBooksResponse, err error) {
	var books []*libraryv1.Book
	_, err = graphify.List(ctx, map[string]interface{}{"author": "F. Scott Fitzgerald"}, &books)
	return &libraryv1.ListBooksResponse{Books: books}, err
}

// createBook is an example of mutation with arguments
func createBook(ctx context.Context, req *libraryv1.Book) (*libraryv1.Book, error) {
	keys, err := graphify.Create(ctx, req)
	if err != nil {
		return nil, err
	}

	req.Key = keys[0]
	return req, nil
}
