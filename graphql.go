package graphify

import (
	"context"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
)

func (g *graph) GraphQLHandler(ctx context.Context) *handler.Handler {
	var beastType = graphql.NewObject(graphql.ObjectConfig{
		Name: "Beast",
		Fields: graphql.Fields{
			"name": &graphql.Field{
				Type: graphql.String,
			},
			"description": &graphql.Field{
				Type: graphql.String,
			},
			"id": &graphql.Field{
				Type: graphql.Int,
			},
			"otherNames": &graphql.Field{
				Type: graphql.NewList(graphql.String),
			},
			"imageUrl": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	var rootQuery = graphql.NewObject(graphql.ObjectConfig{
		Name: "RootQuery",
		Fields: graphql.Fields{
			"beast": &graphql.Field{
				Type:        beastType,
				Description: "Get single beast",
				Args: graphql.FieldConfigArgument{
					"name": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {

					nameQuery, isOK := params.Args["name"].(string)
					if isOK {
						// Search for el with name
						for _, beast := range BeastList {
							if beast.Name == nameQuery {
								return beast, nil
							}
						}
					}

					return Beast{}, nil
				},
			},

			"beastList": &graphql.Field{
				Type:        graphql.NewList(beastType),
				Description: "List of beasts",
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return BeastList, nil
				},
			},
		},
	})

	var BeastSchema, _ = graphql.NewSchema(graphql.SchemaConfig{
		Query: rootQuery,
	})

	return handler.New(&handler.Config{
		Schema:     &BeastSchema,
		Pretty:     true,
		GraphiQL:   false,
		Playground: true,
	})
}

var BeastList = []Beast{
	{ID: 1, Name: "Beast", Description: "The Beast", OtherNames: []string{"Bestia"}, ImageURL: "http://beast.com"},
}

type Beast struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	OtherNames  []string `json:"otherNames"`
	ImageURL    string   `json:"imageUrl"`
}
