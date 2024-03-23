package graphify

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/arangodb/go-driver"
)

type relation struct {
	From string `json:"_from"`
	To   string `json:"_to"`
}

type graph struct {
	// Nodes collection => type
	Nodes map[string]reflect.Type

	// collection => type
	Edges map[string]reflect.Type

	// from => to => collection
	Relations map[string]relation
}

func NewGraph() *graph {
	return &graph{
		Nodes:     make(map[string]reflect.Type),
		Edges:     make(map[string]reflect.Type),
		Relations: make(map[string]relation),
	}
}

func (g *graph) Node(node interface{}) {
	nodeType := reflect.TypeOf(node)
	if nodeType.Kind() != reflect.Struct || !isNode(nodeType) {
		panic(errors.New("node must be a struct with valid fields"))
	}

	nodeName := CollectionFor(nodeType)
	if _, exists := g.Nodes[nodeName]; exists {
		return // ignore nodes that have been already included
	}

	g.Nodes[nodeName] = nodeType
}

func (g *graph) Edge(from, to, edge interface{}) {
	fromType := reflect.TypeOf(from)
	toType := reflect.TypeOf(to)
	edgeType := reflect.TypeOf(edge)

	if fromType.Kind() != reflect.Struct || toType.Kind() != reflect.Struct || edgeType.Kind() != reflect.Struct {
		panic(errors.New("from, to, and edge must be structs"))
	}

	if !isEdge(edgeType) || !isNode(fromType) || !isNode(toType) {
		panic(errors.New("valid edge must relate two valid nodes"))
	}

	fromName := CollectionFor(fromType)
	toName := CollectionFor(toType)
	edgeName := CollectionFor(edgeType)

	if _, exists := g.Nodes[fromName]; !exists {
		panic(errors.New("from node type does not exist"))
	}

	if _, exists := g.Nodes[toName]; !exists {
		panic(errors.New("to node type does not exist"))
	}

	if _, exists := g.Edges[edgeName]; exists {
		panic(errors.New("edge type already exists"))
	}

	g.Relations[edgeName] = relation{From: fromName, To: toName}
	g.Edges[edgeName] = edgeType
}
func (g *graph) AutoMigrate(ctx context.Context) error {
	for _, node := range g.Nodes {
		node := reflect.New(node).Elem()
		if err := Collection(ctx, node.Interface()); err != nil {
			return err
		}
	}
	for _, edge := range g.Edges {
		edge := reflect.New(edge).Elem()
		if err := Collection(ctx, edge.Interface()); err != nil {
			return err
		}
	}
	return nil
}

func Collection(ctx context.Context, elem interface{}, callbacks ...func(context.Context, driver.Collection)) (err error) {
	elemType := reflect.TypeOf(elem)
	elemName := CollectionFor(elemType)

	conn, found := ConnectionFromContext(ctx)
	if !found {
		return fmt.Errorf("connection not provided in context")
	}

	db, err := conn.GetDatabase(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	var col driver.Collection
	if isEdge(elemType) {
		if col, err = createEdgeCollection(ctx, elemName, db); err != nil {
			return err
		}
	} else if isNode(elemType) {
		if col, err = createNodeCollection(ctx, elemName, db); err != nil {
			return err
		}
	} else {
		return errors.New("migrate only nodes and edges")
	}

	for _, callback := range callbacks {
		callback(ctx, col)
	}

	return nil
}

func createNodeCollection(ctx context.Context, name string, db driver.Database) (col driver.Collection, err error) {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		if col, err = db.CreateCollection(ctx, name, nil); err != nil {
			return nil, fmt.Errorf("failed to create collection: %w", err)
		}
		return
	}

	return db.Collection(ctx, name)
}

func createEdgeCollection(ctx context.Context, name string, db driver.Database) (col driver.Collection, err error) {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		if col, err = db.CreateCollection(ctx, name, &driver.CreateCollectionOptions{Type: driver.CollectionTypeEdge}); err != nil {
			return nil, fmt.Errorf("failed to create collection: %w", err)
		}
		return
	}

	return db.Collection(ctx, name)
}

func jsonTag(field reflect.StructField) (name string, omitempty bool) {
	tag := field.Tag.Get("json")
	if len(tag) == 0 {
		return field.Name, false
	}

	parts := strings.SplitN(tag, ",", 2)
	if len(parts) == 1 {
		return parts[0], false
	}

	return parts[0], strings.Contains(parts[1], "omitempty")
}
