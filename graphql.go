package graphify

import (
	"context"
	"reflect"
	"runtime"
	"strings"

	"github.com/amaury95/protoc-gen-graphify/interfaces"
	"github.com/go-openapi/inflect"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
)

func (g *graph) GraphQLHandler(ctx context.Context, handlers ...interface{}) *handler.Handler {
	var queries = graphql.NewObject(graphql.ObjectConfig{
		Name:   "Query",
		Fields: graphql.Fields{},
	})

	var mutations = graphql.NewObject(graphql.ObjectConfig{
		Name:   "Mutation",
		Fields: graphql.Fields{},
	})

	for nodeName, node := range g.Nodes {
		if graphNode, ok := reflect.New(node).Interface().(interfaces.GraphqlObject); ok {
			// inject relationships to node
			for edgeName, relation := range g.Relations {
				if relation.From == nodeName {
					addRelationship(edgeName, nodeName, node, g.Nodes[relation.To], g.Edges[edgeName], DirectionOutbound)
				}
				if relation.To == nodeName {
					addRelationship(edgeName, nodeName, node, g.Nodes[relation.From], g.Edges[edgeName], DirectionInbound)
				}
			}

			// expose public handlers (use only for CMS or testing purpose)
			if g.UseUnsafeHandlers(handlers...) {
				queries.AddFieldConfig(nodeName, &graphql.Field{
					Args: graphql.FieldConfigArgument{
						"count":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 10, Description: "Amount of elements to return"},
						"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Number of elements to skip"},
					},
					Type:    graphql.NewList(graphNode.Object()),
					Resolve: unsafe_ListElements(node),
				})

				queries.AddFieldConfig(inflect.Singularize(nodeName), &graphql.Field{
					Args: graphql.FieldConfigArgument{
						"key": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID), Description: "Key of the element to retrieve"},
					},
					Type:    graphNode.Object(),
					Resolve: unsafe_GetElement(node),
				})
			}
		}
	}

	// add handlers to queries or mutations
	for _, handler := range handlers {
		if query, ok := handler.(Query); ok {
			queries.AddFieldConfig(query.Name, query)
		}
		if mutation, ok := handler.(Mutation); ok {
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

func addRelationship(name, relation string, from, to, edge reflect.Type, direction Direction) {
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
		Args: graphql.FieldConfigArgument{
			"count":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 10, Description: "Amount of elements to return"},
			"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Number of elements to skip"},
		},
		Type: graphql.NewList(graphql.NewObject(graphql.ObjectConfig{
			Name: from.Name() + "_" + inflect.Capitalize(name),
			Fields: graphql.Fields{
				"node": &graphql.Field{Type: toNode.Object()},
				"edge": &graphql.Field{Type: edgeNode.Object()},
			},
		})),
		Resolve: listRelations(relation, to, edge, direction),
	})
}

func listRelations(relation string, to, edge reflect.Type, direction Direction) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		resultType := reflect.StructOf([]reflect.StructField{
			{Name: "Node", Type: to, Tag: reflect.StructTag("json:\"node\"")},
			{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
		})

		key := reflect.ValueOf(p.Source).FieldByName("Key").
			Interface().(string)

		out := reflect.New(reflect.SliceOf(resultType))
		if _, err := Relations(p.Context, getId(relation, key), p.Args, direction, out.Interface()); err != nil {
			return nil, err
		}

		return out.Elem().Interface(), nil
	}
}

func unsafe_ListElements(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		out := reflect.New(reflect.SliceOf(reflect.PointerTo(t)))
		if _, err := List(p.Context, p.Args, out.Interface()); err != nil {
			return nil, err
		}
		return out.Elem().Interface(), nil
	}
}

func unsafe_GetElement(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		key := p.Args["key"].(string)
		out := reflect.New(t)
		if err := Read(p.Context, key, out.Interface()); err != nil {
			return nil, err
		}
		return out.Elem().Interface(), nil
	}
}

// UnsafeHandlers ...
type UnsafeHandlers bool

func (*graph) UnsafeHandlers(value bool) UnsafeHandlers {
	return UnsafeHandlers(value)
}

func (*graph) UseUnsafeHandlers(handlers ...interface{}) bool {
	for _, handler := range handlers {
		if useUnsafe, ok := handler.(UnsafeHandlers); ok && bool(useUnsafe) {
			return true
		}
	}
	return false
}

// Query ...
type Query *graphql.Field

// Query ...
func (*graph) Query(item interface{}) Query {
	return toGraphqlField(item)
}

// Mutation ...
type Mutation *graphql.Field

// Mutation ...
func (*graph) Mutation(item interface{}) Mutation {
	return toGraphqlField(item)
}

func toGraphqlField(item interface{}) *graphql.Field {
	v := reflect.ValueOf(item)
	if v.Kind() != reflect.Func {
		panic("provided item is not a function")
	}

	ft := v.Type()
	// check range for argument and output
	if !(1 <= ft.NumIn() && ft.NumIn() <= 2) || ft.NumOut() != 2 {
		panic("provided function must have at least one argument and exactly two return values")
	}

	// Check if the first argument is Context
	if ft.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		panic("first argument of the function should be context.Context")
	}

	// Check if the first return value implements GraphqlOutput
	output, ok := reflect.New(ft.Out(0).Elem()).Interface().(interfaces.GraphqlOutput)
	if !ok {
		panic("first return value of the function should implement GraphqlOutput")
	}

	// Check if the second return value is an error
	if ft.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		panic("second return value of the function should be an error")
	}

	// Get the name of the function
	name := runtime.FuncForPC(v.Pointer()).Name()
	// Trim the package path
	dotIndex := strings.LastIndex(name, ".")
	if dotIndex != -1 {
		name = name[dotIndex+1:]
	}

	if ft.NumIn() == 2 {
		// Check if the second argument implements GraphqlArgument
		args, ok := reflect.New(ft.In(1).Elem()).Interface().(interfaces.GraphqlArgument)
		if !ok {
			panic("second argument of the function should be utils.GraphqlArgument")
		}

		// Check if the second argument implements Unmarshaler
		if !ft.In(1).Implements(reflect.TypeOf((*interfaces.Unmarshaler)(nil)).Elem()) {
			panic("second argument of the function should implement Unmarshaler")
		}

		// handler with arguments
		return &graphql.Field{
			Name: name,
			Type: output.Output(),
			Args: args.Argument(),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				args := reflect.New(ft.In(1).Elem()).Interface()
				args.(interfaces.Unmarshaler).UnmarshalMap(p.Args)
				result := v.Call([]reflect.Value{reflect.ValueOf(p.Context), reflect.ValueOf(args)})
				if err := result[1].Interface(); err != nil {
					return nil, err.(error)
				}
				return result[0].Interface(), nil
			},
		}
	}

	// handler with no argument
	return &graphql.Field{
		Name: name,
		Type: output.Output(),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			result := v.Call([]reflect.Value{reflect.ValueOf(p.Context)})
			if err := result[1].Interface(); err != nil {
				return nil, err.(error)
			}
			return result[0].Interface(), nil
		},
	}
}
