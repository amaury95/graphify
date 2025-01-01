package graphify

import (
	"context"
	"reflect"

	argument "github.com/amaury95/graphify/pkg/models/domain/argument/v1"
	"github.com/amaury95/protoc-gen-graphify/interfaces"
	"github.com/go-openapi/inflect"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
)

// Empty is ignored from graphql input
type Empty struct{}

func (*Empty) Argument() graphql.FieldConfigArgument {
	return nil
}

// query ...
type query *graphql.Field

// Query ...
func Query[Arg interfaces.GraphqlArgument, Out interfaces.GraphqlOutput](fn func(context.Context, Arg) (Out, error)) query {
	return toHandler(fn)
}

// mutation ...
type mutation *graphql.Field

// Mutation ...
func Mutation[Arg interfaces.GraphqlArgument, Out interfaces.GraphqlOutput](fn func(context.Context, Arg) (Out, error)) mutation {
	return toHandler(fn)
}

func toHandler[Arg interfaces.GraphqlArgument, Out interfaces.GraphqlOutput](fn func(context.Context, Arg) (Out, error)) *graphql.Field {
	fv := reflect.ValueOf(fn)
	ft := fv.Type()

	// Get output instance
	output := reflect.New(ft.Out(0).Elem()).Interface().(interfaces.GraphqlOutput)

	if !ft.In(1).Implements(reflect.TypeOf((*interfaces.Unmarshaler)(nil)).Elem()) {
		// Handler with no argument
		return &graphql.Field{
			Name: funcName(fv),
			Type: output.Output(),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				args := reflect.New(ft.In(1).Elem())
				result := fv.Call([]reflect.Value{reflect.ValueOf(p.Context), args})
				if err := result[1].Interface(); err != nil {
					return nil, err.(error)
				}
				return result[0].Interface(), nil
			},
		}
	}

	// Get argument instance
	arg := reflect.New(ft.In(1).Elem()).Interface().(interfaces.GraphqlArgument)

	// Handler with arguments
	return &graphql.Field{
		Name: funcName(fv),
		Type: output.Output(),
		Args: arg.Argument(),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			args := reflect.New(ft.In(1).Elem()).Interface()
			args.(interfaces.Unmarshaler).UnmarshalMap(p.Args)
			result := fv.Call([]reflect.Value{reflect.ValueOf(p.Context), reflect.ValueOf(args)})
			if err := result[1].Interface(); err != nil {
				return nil, err.(error)
			}
			return result[0].Interface(), nil
		},
	}

}

// exposedNodes ...
type exposedNodes map[string]bool

// ExposeNodes ...
func ExposeNodes(nodes ...any) exposedNodes {
	exposed := make(exposedNodes)
	for _, node := range nodes {
		exposed[collectionFor(reflect.TypeOf(node))] = true
	}
	return exposed
}

func exposingNode(nodeName string, handlers ...interface{}) bool {
	for _, handler := range handlers {
		if exposed, ok := handler.(exposedNodes); ok && (len(exposed) == 0 || exposed[nodeName]) {
			return true
		}
	}
	return false
}

// GraphqlHandler ...
type GraphqlHandler struct {
	access IAccess
	graph  IGraph
}

// NewGraphqlHandler ...
func NewGraphqlHandler(access IAccess, graph IGraph) *GraphqlHandler {
	return &GraphqlHandler{access: access, graph: graph}
}

// Handler ...
func (e *GraphqlHandler) Handler(ctx context.Context, handlers ...interface{}) *handler.Handler {
	var queries = graphql.NewObject(graphql.ObjectConfig{
		Name:   "Query",
		Fields: graphql.Fields{},
	})

	var mutations = graphql.NewObject(graphql.ObjectConfig{
		Name:   "Mutation",
		Fields: graphql.Fields{},
	})

	for _, node := range e.graph.Nodes() {
		if graphNode, ok := reflect.New(node).Interface().(interfaces.GraphqlObject); ok {
			// inject relationships to node
			for _, edge := range e.graph.Edges() {
				relation := e.graph.Relation(edge)

				if relation.From.Name() == node.Name() {
					e.addRelationship(e.graph.CollectionFor(edge), e.graph.CollectionFor(node), node, relation.To, edge, DirectionOutbound)
				}
				if relation.To.Name() == node.Name() {
					e.addRelationship(e.graph.CollectionFor(edge), e.graph.CollectionFor(node), node, relation.From, edge, DirectionInbound)
				}
			}

			// expose public handlers (use only for CMS or testing purpose)
			if exposingNode(e.graph.CollectionFor(node), handlers...) {
				queries.AddFieldConfig(e.graph.CollectionFor(node), &graphql.Field{
					Args:    new(argument.Pagination).Argument(),
					Type:    graphql.NewList(graphNode.Object()),
					Resolve: e.expose_ListElements(node),
				})

				queries.AddFieldConfig(inflect.Singularize(e.graph.CollectionFor(node)), &graphql.Field{
					Args:    new(argument.Key).Argument(),
					Type:    graphNode.Object(),
					Resolve: e.expose_GetElement(node),
				})
			}
		}
	}

	// add handlers to queries or mutations
	for _, handler := range handlers {
		if query, ok := handler.(query); ok {
			queries.AddFieldConfig(query.Name, query)
		}
		if mutation, ok := handler.(mutation); ok {
			mutations.AddFieldConfig(mutation.Name, mutation)
		}
	}

	// add queries and mutations to config
	config := graphql.SchemaConfig{}
	if len(queries.Fields()) > 0 {
		config.Query = queries
	}
	if len(mutations.Fields()) > 0 {
		config.Mutation = mutations
	}

	// create schema
	var schema, err = graphql.NewSchema(config)
	if err != nil {
		panic(err.Error())
	}

	return handler.New(&handler.Config{
		Schema:   &schema,
		GraphiQL: IsDevelopmentContext(ctx),
	})
}

func (e *GraphqlHandler) addRelationship(name, relation string, from, to, edge reflect.Type, direction Direction) {
	fromNode, ok := reflect.New(from).Interface().(interfaces.GraphqlObject)
	if !ok {
		return
	}
	toNode, ok := reflect.New(to).Interface().(interfaces.GraphqlObject)
	if !ok {
		return
	}
	edgeNode, ok := reflect.New(edge).Interface().(interfaces.GraphqlObject)
	if !ok {
		return
	}

	fromNode.Object().AddFieldConfig(name, &graphql.Field{
		Args: new(argument.Pagination).Argument(),
		Type: graphql.NewList(graphql.NewObject(graphql.ObjectConfig{
			Name: from.Name() + "_" + inflect.Capitalize(name),
			Fields: graphql.Fields{
				"node": &graphql.Field{Type: toNode.Object()},
				"edge": &graphql.Field{Type: edgeNode.Object()},
			},
		})),
		Resolve: e.listRelations(relation, to, edge, direction),
	})
}

func (e *GraphqlHandler) listRelations(relation string, to, edge reflect.Type, direction Direction) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		resultType := reflect.StructOf([]reflect.StructField{
			{Name: "Node", Type: to, Tag: reflect.StructTag("json:\"node\"")},
			{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
		})

		key := reflect.ValueOf(p.Source).Elem().FieldByName("Key").
			Interface().(string)

		out := reflect.New(reflect.SliceOf(resultType))
		if _, err := e.access.Relations(p.Context, getId(relation, key), Filter().From(p.Args), direction, out.Interface()); err != nil {
			return nil, err
		}

		return out.Elem().Interface(), nil
	}
}

func (e *GraphqlHandler) expose_ListElements(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		out := reflect.New(reflect.SliceOf(reflect.PointerTo(t)))
		if _, err := e.access.List(p.Context, Filter().From(p.Args), out.Interface()); err != nil {
			return nil, err
		}
		return out.Elem().Interface(), nil
	}
}

func (e *GraphqlHandler) expose_GetElement(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		var args argument.Key
		args.UnmarshalMap(p.Args)

		out := reflect.New(t)
		if err := e.access.Read(p.Context, args.Key, out.Interface()); err != nil {
			return nil, err
		}
		return out.Interface(), nil
	}
}
