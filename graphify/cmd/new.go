/*
Copyright © 2025 Amaury Diaz <amauryuh@gmail.com>
*/
package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var new_module_path string

// newCmd represents the new command
var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new Graphify project",
	Long: `Create a new Graphify project with a given name and 
			module path with an example proto file`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		createProjectStructure(args[0], new_module_path)
	},
}

func init() {
	rootCmd.AddCommand(newCmd)

	newCmd.Flags().StringVarP(&new_module_path, "module", "m", "example.com", "Module path")
}

func createProjectStructure(name string, go_mod_path string) {
	currentDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Join(currentDir, name)
	os.MkdirAll(projectRoot, 0755)

	progress := NewProgress(4)

	// Create project structure
	progress.Print("Creating project structure...")
	for _, file := range []file{
		example_proto_file,
		buf_gen_yaml_file,
		buf_yaml_file,
		main_file,
	} {
		filePath := filepath.Join(projectRoot, file.RelativePath)
		fileTemplate := template.Must(template.New(file.FileName).Parse(file.Content))
		fileBuffer := bytes.NewBuffer(nil)
		fileTemplate.Execute(fileBuffer, map[string]string{
			"module_path": go_mod_path,
		})

		os.MkdirAll(filePath, 0755)
		os.WriteFile(filepath.Join(filePath, file.FileName), fileBuffer.Bytes(), 0644)
	}

	// Go into the project directory
	os.Chdir(projectRoot)

	// Initialize go module
	progress.Print("Initializing go module...")
	go_mod_cmd := exec.Command("go", "mod", "init", go_mod_path)
	go_mod_cmd.Run()

	// Generate proto files
	progress.Print("Generating proto files...")
	buf_generate_cmd := exec.Command("buf", "generate")
	buf_generate_cmd.Run()

	// Tidy go module
	progress.Print("Tidying go module...")
	go_mod_tidy_cmd := exec.Command("go", "mod", "tidy")
	go_mod_tidy_cmd.Run()

	progress.Done("Project created at " + projectRoot)
}

// file represents a file in the project
type file struct {
	RelativePath, FileName, Content string
}

// example_proto_file is the example proto file
var example_proto_file = file{
	RelativePath: "proto/models/v1",
	FileName:     "example.proto",
	Content: `
syntax = "proto3";

package models.v1;

message Example {
  string key = 1 [json_name = "_key"];
  string name = 2;
}
`,
}

// buf_gen_yaml_file is the buf.gen.yaml file
var buf_gen_yaml_file = file{
	RelativePath: "",
	FileName:     "buf.gen.yaml",
	Content: `
version: v2
managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      value: {{.module_path}}/domain
plugins:
  - local: protoc-gen-graphify
    out: domain
    opt: paths=source_relative
`,
}

// buf_yaml_file is the buf.yaml file
var buf_yaml_file = file{
	RelativePath: "",
	FileName:     "buf.yaml",
	Content: `
version: v2
modules:
  - path: proto
lint:
  use:
    - DEFAULT
  except:
    - FIELD_NOT_REQUIRED
    - PACKAGE_NO_IMPORT_CYCLE
  disallow_comment_ignores: true
breaking:
  use:
    - FILE
  except:
    - EXTENSION_NO_DELETE
    - FIELD_SAME_DEFAULT
`,
}

// main_file is the main.go file
var main_file = file{
	RelativePath: "",
	FileName:     "main.go",
	Content: `package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"

	modelsv1 "{{.module_path}}/domain/models/v1"
	"github.com/amaury95/graphify"
	argumentv1 "github.com/amaury95/graphify/pkg/models/domain/argument/v1"
	observerv1 "github.com/amaury95/graphify/pkg/models/domain/observer/v1"
	"github.com/arangodb/go-driver"
	"github.com/gorilla/mux"

	config "github.com/arangodb/go-driver/http"
	"go.uber.org/fx"
)

func main() {
	var (
		dbUrl  = flag.String("url", "http://localhost:8529", "Database URL")
		dbName = flag.String("db", "example", "Database name")
		dbUser = flag.String("user", "graphify", "Database user")
		dbPass = flag.String("pass", "password", "Database password")
		secret = flag.String("secret", "secret", "Passwords secret")
		port   = flag.String("port", ":9091", "Port to listen on")
	)

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
		fx.Provide(
			fx.Annotate(
				graphify.NewObserver[graphify.Topic],
				fx.As(new(graphify.IObserver[graphify.Topic])),
			),
		),

		// Connection
		fx.Supply(
			graphify.ConnectionConfig{
				DBName:     *dbName,
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
			fx.Annotate(
				graphify.NewGraph,
				fx.As(new(graphify.IGraph)),
			),
		),

		// Admin
		fx.Supply(graphify.AdminHandlerConfig{
			Secret: []byte(*secret),
		}),
		fx.Provide(graphify.NewAdminHandler),

		// Graphql
		fx.Provide(graphify.NewGraphqlHandler, NewApp),

		/* setup router */
		fx.Provide(NewRouter),

		/* decorate graph and observer */
		fx.Decorate(DecorateObserver, DecorateGraph),

		/* run http server */
		fx.Invoke(func(ctx context.Context, lc fx.Lifecycle, router *mux.Router) *http.Server {
			srv := &http.Server{
				Addr:        *port,
				Handler:     router,
				BaseContext: func(net.Listener) context.Context { return ctx }, // Inject app context to requests
			}

			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					ln, err := net.Listen("tcp", srv.Addr)
					if err != nil {
						return err
					}

					fmt.Println("Starting HTTP server at", srv.Addr)
					go srv.Serve(ln)

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

func DecorateObserver(observer graphify.IObserver[graphify.Topic]) graphify.IObserver[graphify.Topic] {
	observer.Subscribe(graphify.CreatedTopic.For(modelsv1.Example{}), func(e *graphify.Event[graphify.Topic]) error {
		// Cast payload
		payload := e.Payload.(*observerv1.CreatedPayload)

		// Unmarshal element
		var item modelsv1.Example
		payload.Element.UnmarshalTo(&item)

		// Log
		fmt.Printf("Created item: %s with key: %s", item.Name, payload.Key)
		return nil
	})

	return observer
}

func DecorateGraph(ctx context.Context, graph graphify.IGraph, access graphify.IAccess) graphify.IGraph {
	graph.Node(modelsv1.Example{})

	// Ensure hash index on name
	access.Collection(ctx, modelsv1.Example{}, func(ctx context.Context, c driver.Collection) {
		c.EnsureHashIndex(ctx, []string{"name"}, &driver.EnsureHashIndexOptions{Unique: true})
	})

	// Auto migrate graph
	if err := access.AutoMigrate(ctx, graph); err != nil {
		panic(err)
	}
	return graph
}

func NewRouter(ctx context.Context, admin *graphify.AdminHandler, graphql *graphify.GraphqlHandler, app *App) *mux.Router {
	router := mux.NewRouter()

	// Dashboard
	router.PathPrefix("/dashboard").
		Handler(admin.Handler(ctx))

	// Graphql
	router.PathPrefix("/graphql").Handler(
		graphql.Handle(ctx,
			graphify.ExposeNodes(modelsv1.Example{}),
			graphify.Mutation(app.createExample),
			/* add functions here */
		))

	return router
}

// App is the application struct
type App struct{ access graphify.IAccess }

func NewApp(access graphify.IAccess) *App {
	return &App{access: access}
}

func (a *App) createExample(ctx context.Context, req *modelsv1.Example) (*argumentv1.Keys, error) {
	keys, err := a.access.Create(ctx, req)
	if err != nil {
		return nil, err
	}

	return &argumentv1.Keys{Keys: keys}, nil
}
`,
}

// progress represents a logger that manages progress and step logs.
type progress struct {
	bar *progressbar.ProgressBar
}

// NewProgress initializes a new Logger.
func NewProgress(totalSteps int) *progress {
	bar := progressbar.NewOptions(totalSteps,
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("Setting up project"),
	)

	return &progress{bar: bar}
}

// Print logs a step message and updates progress.
func (l *progress) Print(message string) {
	// Print the step message and update the progress bar
	fmt.Printf("\r%s", message)
	l.bar.Add(1)
}

// Done stops the logger and completes the progress bar.
func (l *progress) Done(message string) {
	l.bar.Finish()
	fmt.Println("\n", message)
}
