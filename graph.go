package graphify

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/arangodb/go-driver"
)

type graph struct {
	comm *Common

	// Nodes collection => type
	Nodes map[string]reflect.Type
	// Private nodes (not added to endpoints) collection => type
	privateNodes map[string]reflect.Type

	// collection => type
	Edges map[string]reflect.Type

	// from => to => collection
	Relations map[string]map[string]string
}

func NewGraph(comm *Common) *graph {
	return &graph{
		Nodes:        make(map[string]reflect.Type),
		privateNodes: make(map[string]reflect.Type),
		Edges:        make(map[string]reflect.Type),
		Relations:    make(map[string]map[string]string),
		comm:         comm,
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

	// Check if the relationship between from and to does not exist
	if _, exists := g.Relations[fromName]; exists {
		if _, exists := g.Relations[fromName][toName]; exists {
			panic(errors.New("relationship between from and to already exists"))
		}
	} else {
		g.Relations[fromName] = make(map[string]string)
	}

	g.Relations[fromName][toName] = edgeName
	g.Edges[edgeName] = edgeType
}

func (g *graph) AutoMigrate(ctx context.Context) error {
	db, err := g.comm.Connection.GetDatabase(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	for collection := range g.Nodes {
		if err := g.createNodeCollection(ctx, collection, db); err != nil {
			return fmt.Errorf("failed to create node: %w", err)
		}
	}

	for collection := range g.privateNodes {
		if err := g.createNodeCollection(ctx, collection, db); err != nil {
			return fmt.Errorf("failed to create node: %w", err)
		}
	}

	for collection := range g.Edges {
		if err := g.createEdgeCollection(ctx, collection, db); err != nil {
			return fmt.Errorf("failed to create edge: %w", err)
		}
	}

	return nil
}

func (g *graph) createNodeCollection(ctx context.Context, collection string, db driver.Database) error {
	exists, err := db.CollectionExists(ctx, collection)
	if err != nil {
		return fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		if _, err := db.CreateCollection(ctx, collection, nil); err != nil {
			return fmt.Errorf("failed to create collection: %w", err)
		}
	}

	return nil
}

func (g *graph) createEdgeCollection(ctx context.Context, collection string, db driver.Database) error {
	exists, err := db.CollectionExists(ctx, collection)
	if err != nil {
		return fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		if _, err := db.CreateCollection(ctx, collection, &driver.CreateCollectionOptions{
			Type: driver.CollectionTypeEdge,
		}); err != nil {
			return fmt.Errorf("failed to create collection: %w", err)
		}
	}

	return nil
}
