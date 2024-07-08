package graphify

import (
	"errors"
	"reflect"

	"github.com/samber/lo"
)

// Relation
type Relation struct {
	From reflect.Type `json:"_from"`
	To   reflect.Type `json:"_to"`
}

// IGraph ...
type IGraph interface {
	// Node ...
	Node(node any)
	// Edge ...
	Edge(from, to, edge any)
	
	// Nodes ...
	Nodes() []reflect.Type
	// Edges ...
	Edges() []reflect.Type
	// Relation ...
	Relation(edge reflect.Type) *Relation

	// CollectionFor ...
	CollectionFor(elem reflect.Type) string
	// TypeOf ...
	TypeOf(colection string) reflect.Type
}

// Graph ...
type Graph struct {
	// nodes collection => type
	nodes map[string]reflect.Type

	// collection => type
	edges map[string]reflect.Type

	// edge => relation
	relations map[string]*Relation
}

// NewGraph ...
func NewGraph() *Graph {
	return &Graph{
		nodes:     make(map[string]reflect.Type),
		edges:     make(map[string]reflect.Type),
		relations: make(map[string]*Relation),
	}
}

// interface check for Graph
var _ IGraph = new(Graph)

// Nodes ...
func (g *Graph) Nodes() []reflect.Type {
	return lo.Values(g.nodes)
}

// Edges ...
func (g *Graph) Edges() []reflect.Type {
	return lo.Values(g.edges)
}

// Relation ...
func (g *Graph) Relation(edge reflect.Type) *Relation {
	return g.relations[g.CollectionFor(edge)]
}

// TypeOf ...
func (g *Graph) TypeOf(collection string) reflect.Type {
	if t, found := g.nodes[collection]; found {
		return t
	}
	if t, found := g.edges[collection]; found {
		return t
	}
	return nil
}

// CollectionFor ...
func (g *Graph) CollectionFor(t reflect.Type) string {
	return collectionFor(t)
}

// Node ...
func (g *Graph) Node(node any) {
	nodeType := reflect.TypeOf(node)
	if nodeType.Kind() != reflect.Struct || !isNode(nodeType) {
		panic(errors.New("node must be a struct with valid fields"))
	}

	nodeName := g.CollectionFor(nodeType)
	if _, exists := g.nodes[nodeName]; exists {
		return // ignore nodes that have been already included
	}

	g.nodes[nodeName] = nodeType
}

// Edge ...
func (g *Graph) Edge(from, to, edge any) {
	fromType := reflect.TypeOf(from)
	toType := reflect.TypeOf(to)
	edgeType := reflect.TypeOf(edge)

	if fromType.Kind() != reflect.Struct || toType.Kind() != reflect.Struct || edgeType.Kind() != reflect.Struct {
		panic(errors.New("from, to, and edge must be structs"))
	}

	if !isEdge(edgeType) || !isNode(fromType) || !isNode(toType) {
		panic(errors.New("valid edge must relate two valid nodes"))
	}

	fromName := g.CollectionFor(fromType)
	toName := g.CollectionFor(toType)
	edgeName := g.CollectionFor(edgeType)

	if _, exists := g.nodes[fromName]; !exists {
		panic(errors.New("from node type does not exist"))
	}

	if _, exists := g.nodes[toName]; !exists {
		panic(errors.New("to node type does not exist"))
	}

	if _, exists := g.edges[edgeName]; exists {
		panic(errors.New("edge type already exists"))
	}

	g.relations[edgeName] = &Relation{From: fromType, To: toType}
	g.edges[edgeName] = edgeType
}
