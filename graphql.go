package graphify

import (
	"context"
	"reflect"

	"github.com/amaury95/protoc-gen-graphify/utils"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
)

func (g *graph) GraphQLHandler(ctx context.Context, handlers ...interface{}) *handler.Handler {
	var query = graphql.NewObject(graphql.ObjectConfig{
		Name:   "Query",
		Fields: graphql.Fields{},
	})

	for nodeName, node := range g.Nodes {
		if graphNode, ok := reflect.New(node).Interface().(utils.GraphqlQuery); ok {
			query.AddFieldConfig(nodeName, &graphql.Field{
				Type:    graphql.NewList(graphNode.QueryObject()),
				Resolve: listElements(node),
			})
		}
	}

	var schema, err = graphql.NewSchema(graphql.SchemaConfig{Query: query})
	if err != nil {
		panic(err.Error())
	}

	return handler.New(&handler.Config{
		Schema:   &schema,
		GraphiQL: true,
	})
}

func listElements(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		out := reflect.New(reflect.SliceOf(t))
		if _, err := List(p.Context, nil, out.Interface()); err != nil {
			return nil, err
		}
		return out.Elem().Interface(), nil
	}
}
