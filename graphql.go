package graphify

import (
	"context"
	"reflect"

	"github.com/amaury95/protoc-gen-graphify/utils"
	"github.com/go-openapi/inflect"
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
			for edgeName, relation := range g.Relations {
				if relation.From == nodeName {
					addRelationship(edgeName, nodeName, node, g.Nodes[relation.To], g.Edges[edgeName], DirectionOutbound)
				}
				if relation.To == nodeName {
					addRelationship(edgeName, nodeName, node, g.Nodes[relation.From], g.Edges[edgeName], DirectionInbound)
				}
			}

			query.AddFieldConfig(nodeName, &graphql.Field{
				Args: graphql.FieldConfigArgument{
					"count":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 10, Description: "Amount of elements to return"},
					"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Number of elements to skip"},
				},
				Type:    graphql.NewList(graphNode.QueryObject()),
				Resolve: listElements(node),
			})

			query.AddFieldConfig(inflect.Singularize(nodeName), &graphql.Field{
				Args: graphql.FieldConfigArgument{
					"key": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID), Description: "Key of the element to retrieve"},
				},
				Type:    graphNode.QueryObject(),
				Resolve: getElement(node),
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

func addRelationship(name, relation string, from, to, edge reflect.Type, direction Direction) {
	fromNode, ok := reflect.New(from).Interface().(utils.GraphqlQuery)
	if !ok {
		return
	}
	toNode, ok := reflect.New(to).Interface().(utils.GraphqlQuery)
	if !ok {
		return
	}
	edgeNode, ok := reflect.New(edge).Interface().(utils.GraphqlQuery)
	if !ok {
		return
	}

	fromNode.QueryObject().AddFieldConfig(name, &graphql.Field{
		Args: graphql.FieldConfigArgument{
			"count":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 10, Description: "Amount of elements to return"},
			"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Number of elements to skip"},
		},
		Type: graphql.NewList(graphql.NewObject(graphql.ObjectConfig{
			Name: from.Name() + "_" + inflect.Capitalize(name),
			Fields: graphql.Fields{
				"node": &graphql.Field{Type: toNode.QueryObject()},
				"edge": &graphql.Field{Type: edgeNode.QueryObject()},
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

func listElements(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		out := reflect.New(reflect.SliceOf(t))
		if _, err := List(p.Context, p.Args, out.Interface()); err != nil {
			return nil, err
		}
		return out.Elem().Interface(), nil
	}
}

func getElement(t reflect.Type) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		key := p.Args["key"].(string)
		out := reflect.New(t)
		if err := Read(p.Context, key, out.Interface()); err != nil {
			return nil, err
		}
		return out.Elem().Interface(), nil
	}
}
