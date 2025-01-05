package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"

	"github.com/amaury95/graphify"
	libraryv1 "github.com/amaury95/graphify/example/domain/library/v1"
	relationv1 "github.com/amaury95/graphify/example/domain/relation/v1"
	observerv1 "github.com/amaury95/graphify/pkg/models/domain/observer/v1"
	"github.com/arangodb/go-driver"
	"github.com/gorilla/mux"
	"github.com/rs/cors"

	config "github.com/arangodb/go-driver/http"
	"go.uber.org/fx"
)

func main() {
	dbUrl := flag.String("db", `http://localhost:8529`, "Database URL")
	dbUser := flag.String("user", "graphify", "Database user")
	dbPass := flag.String("pass", "password", "Database password")
	useTLS := flag.Bool("tls", false, "Use TLS")
	flag.Parse()

	fx.New(
		// Context
		fx.Provide(func() context.Context {
			return graphify.DevelopmentContext(context.Background())
		}),

		// Storage
		fx.Supply(graphify.FilesystemStorageConfig{
			BasePath:  "./uploads",
			MaxMemory: 10 << 20, // 10 MB limit
		}),
		fx.Provide(
			fx.Annotate(
				graphify.NewFilesystemStorage,
				fx.As(new(graphify.IFileStorage)),
			),
		),

		// Observer
		fx.Provide(func() graphify.IObserver[graphify.Topic] {
			observer := graphify.NewObserver[graphify.Topic]()
			observer.Subscribe(
				graphify.CreatedTopic.For(libraryv1.Book{}), logCreatedBook)

			return observer
		}),

		// Connection
		fx.Supply(
			graphify.ConnectionConfig{
				DBName:     "library",
				UserName:   *dbUser,
				Password:   *dbPass,
				Connection: config.ConnectionConfig{Endpoints: []string{*dbUrl}},
			}),
		fx.Provide(
			fx.Annotate(
				graphify.NewConnection,
				fx.As(new(graphify.IConnection)),
			),
		),

		// Access
		fx.Provide(
			fx.Annotate(
				graphify.NewArangoAccess,
				fx.As(new(graphify.IAccess)),
			),
		),

		// Graph
		fx.Provide(
			func(ctx context.Context, access graphify.IAccess) graphify.IGraph {
				graph := graphify.NewGraph()

				graph.Node(libraryv1.Book{})
				graph.Node(libraryv1.Client{})
				graph.Node(libraryv1.Library{})
				graph.Edge(libraryv1.Client{}, libraryv1.Book{}, relationv1.Borrow{})

				access.Collection(ctx, libraryv1.Library{}, func(ctx context.Context, c driver.Collection) {
					c.EnsureGeoIndex(ctx, []string{"location"}, &driver.EnsureGeoIndexOptions{})
				})
				access.AutoMigrate(ctx, graph)
				return graph
			},
		),

		// Admin
		fx.Supply(graphify.AdminHandlerConfig{
			Secret: []byte("secret"),
		}),
		fx.Provide(graphify.NewAdminHandler),

		// Graphql
		fx.Provide(graphify.NewGraphqlHandler, NewHandlers),

		/* setup router */
		fx.Provide(func(ctx context.Context, admin *graphify.AdminHandler, graphql *graphify.GraphqlHandler, handlers *handlers) *mux.Router {
			router := mux.NewRouter()

			router.PathPrefix("/dashboard").
				Handler(admin.Handler(ctx))

			router.PathPrefix("/graphql").Handler(
				graphql.Handler(ctx,
					// graphify.ExposeNodes(libraryv1.Book{}, libraryv1.Library{}),
					graphify.ExposeNodes(),
					graphify.Query(handlers.fitzgeraldBooks),
					graphify.Mutation(handlers.createBook),
				))

			return router
		}),

		/* run http server */
		fx.Invoke(func(ctx context.Context, lc fx.Lifecycle, router *mux.Router) *http.Server {
			// Use cors middleware
			c := cors.New(cors.Options{
				AllowOriginFunc:  func(origin string) bool { return true },
				AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"*"},
				AllowCredentials: true,
			})

			srv := &http.Server{
				Addr:        ":9090",
				Handler:     c.Handler(router),
				BaseContext: func(net.Listener) context.Context { return ctx }, // Inject app context to requests
			}

			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					ln, err := net.Listen("tcp", srv.Addr)
					if err != nil {
						return err
					}

					if *useTLS { // Use TLS

						cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
						if err != nil {
							return fmt.Errorf("error loading TLS cert: %v", err)
						}

						srv.TLSConfig = &tls.Config{
							Certificates: []tls.Certificate{cert},
							MinVersion:   tls.VersionTLS12,
						}

						fmt.Println("Starting HTTPS server at", srv.Addr)
						go srv.ServeTLS(ln, "", "") // Empty strings since we configured TLS above
					} else { // Use HTTP
						fmt.Println("Starting HTTP server at", srv.Addr)
						go srv.Serve(ln)
					}

					return nil
				},
				OnStop: func(ctx context.Context) error {
					return srv.Shutdown(ctx)
				},
			})

			return srv
		}),
	).Run()
}

// logCreatedBook ...
func logCreatedBook(e *graphify.Event[graphify.Topic]) error {
	payload, ok := e.Payload.(*observerv1.CreatedPayload)
	if !ok {
		return fmt.Errorf("payload is not CreatedPayload")
	}
	var book libraryv1.Book
	if err := payload.Element.UnmarshalTo(&book); err != nil {
		return err
	}
	fmt.Printf("Created book: %s with key: %s", book.Title, payload.Key)
	return nil
}

/* Define new handlers */
type handlers struct{ access graphify.IAccess }

func NewHandlers(access graphify.IAccess) *handlers {
	return &handlers{access: access}
}

// fitzgeraldBooks is an example of query without arguments
func (h *handlers) fitzgeraldBooks(ctx context.Context, _ *graphify.Empty) (resp *libraryv1.ListBooksResponse, err error) {
	var books []*libraryv1.Book
	_, err = h.access.List(ctx, graphify.Filter("author", "F. Scott Fitzgerald"), &books)
	return &libraryv1.ListBooksResponse{Books: books}, err
}

// createBook is an example of mutation with arguments
func (h *handlers) createBook(ctx context.Context, req *libraryv1.Book) (*libraryv1.Book, error) {
	keys, err := h.access.Create(ctx, req)
	if err != nil {
		return nil, err
	}

	req.Key = keys[0]
	return req, nil
}
