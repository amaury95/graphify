package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	// "os"

	// "golang.org/x/term"

	"github.com/amaury95/graphify"
	libraryv1 "github.com/amaury95/graphify/example/domain/library/v1"
	observerv1 "github.com/amaury95/graphify/models/domain/observer/v1"
	"github.com/arangodb/go-driver"
	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"
)

func main() {
	var (
		username string
		password []byte
		err      error
	)
	// // Prompt for username
	// fmt.Print("Enter ArangoDB username: ")
	// fmt.Scanln(&username)

	// // Prompt for password
	// fmt.Print("Enter password: ")
	// password, err = term.ReadPassword(int(os.Stdin.Fd()))
	// if err != nil {
	// 	fmt.Println("Error reading password:", err)
	// 	return
	// }

	// Define app context
	ctx := graphify.DevelopmentContext(context.Background())

	// Configure app context
	ctx = graphify.ContextWithConnection(ctx,
		graphify.NewConnection(
			graphify.DatabaseConfig{DBName: "library", UserName: username, Password: string(password)}))

	ctx = graphify.ContextWithObserver(ctx,
		graphify.NewObserver[graphify.Topic]())

	ctx = graphify.ContextWithStorage(ctx,
		graphify.NewFilesystemStorage("./uploads", 10<<20)) // 10 MB limit

	// Create and define graph
	graph := graphify.NewGraph()

	graph.Node(libraryv1.Book{})
	graph.Node(libraryv1.Client{})
	graph.Node(libraryv1.Library{})
	graph.Edge(libraryv1.Client{}, libraryv1.Book{}, libraryv1.Borrow{})

	graphify.Collection(ctx, libraryv1.Library{}, func(ctx context.Context, c driver.Collection) {
		c.EnsureGeoIndex(ctx, []string{"location"}, &driver.EnsureGeoIndexOptions{})
	})
	graph.AutoMigrate(ctx)

	// Seed
	seed(ctx)
	
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
		graph.GraphQLHandler(ctx))

	// Create a server with the given multiplexer
	server := &http.Server{
		Addr:        ":8080",
		Handler:     router,
		BaseContext: func(net.Listener) context.Context { return ctx }, // Inject app context to requests
	}

	// Serve handlers
	fmt.Println("\nServer is listening on :8080")
	if err = server.ListenAndServe(); err != nil {
		fmt.Println("Error:", err)
	}
}

func seed(ctx context.Context) {
	now := time.Now().Unix()

	graphify.Delete(ctx, &libraryv1.Book{Key: "100"})
	graphify.Create(ctx, &libraryv1.Book{
		Key:    "100",
		Title:  "The Great Gatsby",
		Author: "F. Scott Fitzgerald",
		Type: &libraryv1.Book_Novel_{
			Novel: &libraryv1.Book_Novel{
				Genre:           "Fiction",
				PublicationYear: 1925,
			},
		},
		MainReview: &libraryv1.Book_Review{
			Message:  "Review",
			UserName: "Name",
		},
		Reviews: []*libraryv1.Book_Review{
			{Message: "List", UserName: "User List"},
		},
		Tags: []string{"action", "fiction"},
		BookPrice: map[string]int32{
			"new":  200,
			"used": 100,
		},
		Chapters: map[int32]string{
			1: "The Phantom Menace",
			2: "Attack of the Clones",
		},
		Portrait: []byte("https://picsum.photos/200/300"),
		Gallery:  [][]byte{[]byte("https://picsum.photos/200/300"), []byte("https://picsum.photos/200/300")},
		Characters: map[string]*libraryv1.Character{
			"J. Gatsby": {Name: "J. Gatsby", Role: "Main Character"},
		},
		Category: 1,

		Role: &libraryv1.Book_Other{
			Other: "moderator",
		},
	})

	graphify.Delete(ctx, &libraryv1.Client{Key: "100"})
	graphify.Create(ctx, &libraryv1.Client{Key: "100", Name: "Gabriela", Email: "gabi.santacruzpacheco@gmail.com", Member: true})

	graphify.Delete(ctx, &libraryv1.Borrow{Key: "100"})
	graphify.Create(ctx, &libraryv1.Borrow{Key: "100", From: "clients/100", To: "books/100", Date: &now})
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
