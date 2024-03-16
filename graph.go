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
	// Private nodes (not added to endpoints) collection => type
	privateNodes map[string]reflect.Type

	// collection => type
	Edges map[string]reflect.Type

	// from => to => collection
	Relations map[string]relation
}

func NewGraph() *graph {
	return &graph{
		Nodes:        make(map[string]reflect.Type),
		privateNodes: make(map[string]reflect.Type),
		Edges:        make(map[string]reflect.Type),
		Relations:    make(map[string]relation),
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

func (g *graph) HiddenNode(node interface{}) {
	nodeType := reflect.TypeOf(node)
	if nodeType.Kind() != reflect.Struct || !isNode(nodeType) {
		panic(errors.New("node must be a struct with valid fields"))
	}

	nodeName := CollectionFor(nodeType)
	if _, exists := g.Nodes[nodeName]; exists {
		panic(errors.New("node has been added as public node"))
	}

	g.privateNodes[nodeName] = nodeType
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
	conn, found := ConnectionFromContext(ctx)
	if !found {
		return fmt.Errorf("connection not provided in context")
	}

	db, err := conn.GetDatabase(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	for col, elem := range g.Nodes {
		if err := g.createNodeCollection(ctx, col, elem, db); err != nil {
			return fmt.Errorf("failed to create node: %w", err)
		}
	}

	for col, elem := range g.privateNodes {
		if err := g.createNodeCollection(ctx, col, elem, db); err != nil {
			return fmt.Errorf("failed to create node: %w", err)
		}
	}

	for col, elem := range g.Edges {
		if err := g.createEdgeCollection(ctx, col, elem, db); err != nil {
			return fmt.Errorf("failed to create edge: %w", err)
		}
	}

	return nil
}

func (g *graph) createNodeCollection(ctx context.Context, name string, elem reflect.Type, db driver.Database) error {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		col, err := db.CreateCollection(ctx, name, nil)
		if err != nil {
			return fmt.Errorf("failed to create collection: %w", err)
		}

		if field := g.LocationField(elem); field != nil {
			g.indexGeoLocation(ctx, col, *field)
		}
	}

	return nil
}

func (g *graph) createEdgeCollection(ctx context.Context, name string, elem reflect.Type, db driver.Database) error {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		col, err := db.CreateCollection(ctx, name, &driver.CreateCollectionOptions{
			Type: driver.CollectionTypeEdge,
		})
		if err != nil {
			return fmt.Errorf("failed to create collection: %w", err)
		}

		if field := g.LocationField(elem); field != nil {
			g.indexGeoLocation(ctx, col, *field)
		}
	}

	return nil
}

func (g *graph) LocationField(elem reflect.Type) *string {
	field, found := elem.FieldByName("Location")
	if !found {
		return nil
	}

	if field.Type.Kind() != reflect.Pointer {
		return nil
	}

	if field.Type.Elem().Kind() != reflect.Struct {
		return nil
	}

	if field.Type.Elem().NumField() < 2 {
		return nil
	}

	if lat, found := field.Type.Elem().FieldByName("Lat"); !found || lat.Type.Kind() != reflect.Float32 {
		return nil
	}

	if lng, found := field.Type.Elem().FieldByName("Lng"); !found || lng.Type.Kind() != reflect.Float32 {
		return nil
	}

	name, _ := jsonTag(field)
	return &name
}

func (*graph) indexGeoLocation(ctx context.Context, col driver.Collection, field string) {
	col.EnsureGeoIndex(ctx, []string{field}, &driver.EnsureGeoIndexOptions{})
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
