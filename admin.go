package graphify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/amaury95/graphify/models/domain/admin/v1"
	graphify "github.com/amaury95/protoc-gen-graphify/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

const configName = "config.json"

var secretKey = []byte("secret")

func (g *graph) RestHandler(ctx context.Context) http.Handler {
	g.Node(adminv1.Admin{})
	g.HiddenNode(adminv1.AdminPassword{})

	g.AutoMigrate(ctx)

	router := fiber.New(fiber.Config{
		BodyLimit: 10 << 20,
	})
	router.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(string) bool { return true },
		AllowCredentials: true,
	}))
	router.Use(g.contextMiddleware(ctx))
	router.Use(g.authMiddleware)

	admin := router.Group("/admin")
	admin.Get("/schema", g.adminSchemaHandler)
	admin.Get("/config", g.adminConfigHandler)
	admin.Post("/config", g.adminConfigInitHandler)

	auth := admin.Group("/auth")
	auth.Get("/account", g.authAccountHandler)
	auth.Post("/login", g.authLoginHandler)
	auth.Post("/register", g.authRegisterHandler)
	auth.Post("/logout", g.authLogoutHandler)

	resources := admin.Group("/:resource")
	resources.Get("", g.resourcesListHandler)
	resources.Post("", g.resourcesCreateHandler)
	resources.Get("/:key", g.resourcesGetHandler)
	resources.Put("/:key", g.resourcesUpdateHandler)
	resources.Delete("/:key", g.resourcesDeleteHandler)
	resources.Get("/:key/:relation", g.resourcesRelationHandler)

	if _, found := StorageFromContext(ctx); found {
		files := admin.Group("/files")
		files.Post("/upload", g.filesUploadHandler)
		files.Get("/download/:name", g.filesDownloadHandler)
	}

	return adaptor.FiberApp(router)
}

func (g *graph) contextMiddleware(ctx context.Context) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func (g *graph) authMiddleware(c *fiber.Ctx) error {
	// Read the JWT token from the HTTP-only cookie
	cookie := c.Cookies("jwt")
	if cookie == "" {
		return c.Next()
	}

	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil || !token.Valid {
		return fiber.NewError(fiber.StatusUnauthorized)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "invalid token claims")
	}

	var admin adminv1.Admin
	if err := Read(c.UserContext(), claims.Subject, &admin); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	c.SetUserContext(ContextWithAdmin(c.UserContext(), &admin))

	return c.Next()
}

/* Rest Handlers */
func (g *graph) authAccountHandler(c *fiber.Ctx) error {
	admin, found := AdminFromContext(c.UserContext())
	if !found {
		return fiber.NewError(fiber.StatusUnauthorized)
	}

	return c.JSON(&admin)
}

func (g *graph) authLoginHandler(c *fiber.Ctx) error {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	var admins []adminv1.Admin
	if _, err := List(c.UserContext(), &admins, map[string]interface{}{"email": request.Email}); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	if len(admins) == 0 {
		return fiber.NewError(fiber.StatusNotFound)

	}

	var password adminv1.AdminPassword
	if err := Read(c.UserContext(), admins[0].Key, &password); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword(password.PasswordHash, []byte(request.Password)); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	expiresAt := time.Now().Add(10 * time.Hour)

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Subject:   admins[0].Key,
	})

	token, err := claims.SignedString(secretKey)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	c.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  expiresAt,
		HTTPOnly: true,
		SameSite: "None", // TODO: Remove on production
		Secure:   false,  // TODO: Remove on production
	})

	return c.SendStatus(fiber.StatusOK)
}

func (g *graph) authLogoutHandler(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		SameSite: "None", // TODO: Remove on production
		Secure:   false,  // TODO: Remove on production
	})
	return c.SendStatus(fiber.StatusOK)
}

func (g *graph) authRegisterHandler(c *fiber.Ctx) error {
	if _, found := AdminFromContext(c.Context()); !found {
		return fiber.NewError(fiber.StatusUnauthorized)
	}

	var request struct {
		Admin    adminv1.Admin `json:"admin"`
		Password string        `json:"password"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), 14)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	keys, err := Create(c.UserContext(), request.Admin)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if _, err := Create(c.UserContext(), adminv1.AdminPassword{Key: keys[0], PasswordHash: password}); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.SendStatus(fiber.StatusCreated)
}

func (g *graph) resourcesListHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	var keys []string

	elemType, found := g.getElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elems := reflect.New(reflect.SliceOf(elemType))

	if len(keys) > 0 {
		if err := ListKeys(c.UserContext(), keys, elems.Interface()); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		} else {
			return c.JSON(elems.Interface())
		}
	}

	if _, err := List(c.UserContext(), elems.Interface(), nil); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(elems.Interface())
}

func (g *graph) resourcesGetHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")

	elemType, found := g.getElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elem := reflect.New(elemType)
	if err := Read(c.UserContext(), key, elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(elem.Interface())
}

func (g *graph) resourcesCreateHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")

	elemType, found := g.getElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(c.Body(), &data); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	elem := reflect.New(elemType)
	if loader, ok := elem.Interface().(graphify.IMapLoader); ok {
		loader.LoadMap(data)
	}
	keys, err := Create(c.UserContext(), elem.Elem().Interface())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	c.Status(fiber.StatusCreated)
	return c.JSON(keys)
}

func (g *graph) resourcesUpdateHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")

	elemType, found := g.getElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(c.Body(), &data); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	elem := reflect.New(elemType)
	if loader, ok := elem.Interface().(graphify.IMapLoader); ok {
		loader.LoadMap(data)
	}
	if err := Update(c.UserContext(), key, elem.Elem().Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.SendStatus(fiber.StatusOK)
}

func (g *graph) resourcesDeleteHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")

	elemType, found := g.getElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elem := reflect.New(elemType).Elem()
	elem.FieldByName("Key").Set(reflect.ValueOf(key))
	if err := Delete(c.UserContext(), elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.SendStatus(fiber.StatusOK)
}

func (g *graph) resourcesRelationHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")
	collection := c.Params("relation")

	relation, ok := g.Relations[collection]
	if !ok {
		return fiber.NewError(fiber.StatusNotFound)
	}

	edge, from, to := g.Edges[collection], g.Nodes[relation.From], g.Nodes[relation.To]
	if CollectionFor(from) != resource {
		return fiber.NewError(fiber.StatusNotFound)
	}

	resultType := reflect.StructOf([]reflect.StructField{
		{Name: "Node", Type: to, Tag: reflect.StructTag("json:\"node\"")},
		{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
	})

	elems := reflect.New(reflect.SliceOf(resultType))
	if _, err := Relations(c.UserContext(), getId(resource, key), elems.Interface(), map[string]interface{}{}); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(elems.Interface())
}

/* Specs Handlers */
func (g *graph) adminSchemaHandler(c *fiber.Ctx) error {
	// nodes
	nodes := map[string]interface{}{}
	for name, nodeType := range g.Nodes {
		node := reflect.New(nodeType).Interface()
		if spec, ok := node.(graphify.ISchema); ok {
			nodes[name] = spec.Schema()
		}
	}

	// edges
	edges := map[string]interface{}{}
	for name, edgeType := range g.Edges {
		edge := reflect.New(edgeType).Interface()
		if spec, ok := edge.(graphify.ISchema); ok {
			edges[name] = spec.Schema()
		}
	}

	// result
	result := map[string]interface{}{
		"nodes":     nodes,
		"edges":     edges,
		"relations": g.Relations,
	}

	return c.JSON(result)
}

/* Config Handlers */
func (g *graph) adminConfigInitHandler(c *fiber.Ctx) error {
	storage, found := StorageFromContext(c.UserContext())
	if !found {
		return fmt.Errorf("storage not found in context")
	}

	if _, err := storage.ReadFile(configName); err == nil {
		return fiber.NewError(fiber.StatusNotFound)
	}

	var request ApplicationConfig
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	cnf, _ := json.Marshal(request)
	if err := storage.StoreFile(configName, cnf); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.SendStatus(fiber.StatusCreated)
}

func (g *graph) adminConfigHandler(c *fiber.Ctx) error {
	storage, found := StorageFromContext(c.UserContext())
	if !found {
		return fmt.Errorf("storage not found in context")
	}

	conf, err := storage.ReadFile(configName)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	c.Set("Content-Type", "application/json")
	return c.Send(conf)
}

/* Files Handlers */
func (g *graph) filesUploadHandler(c *fiber.Ctx) error {
	storage, found := StorageFromContext(c.UserContext())
	if !found {
		return fmt.Errorf("storage not found in context")
	}

	form, err := c.MultipartForm()
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	files, found := form.Value["file"]
	if !found {
		return fiber.NewError(fiber.StatusBadRequest, "file not provided")
	}

	hashes := []string{}
	for _, file := range files {
		hash, err := storage.StoreByHash([]byte(file))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		hashes = append(hashes, hash)
	}

	return c.JSON(hashes)
}

func (g *graph) filesDownloadHandler(c *fiber.Ctx) error {
	storage, found := StorageFromContext(c.UserContext())
	if !found {
		return fmt.Errorf("storage not found in context")
	}

	name := c.Params("name")

	fileContent, err := storage.ReadFile(name)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Set the Content-Type header based on the file type or use application/octet-stream
	fileHeader := make([]byte, 512)
	copy(fileHeader, fileContent)
	fileContentType := http.DetectContentType(fileHeader)

	// Set the appropriate Content-Disposition header for download
	c.Set("Content-Disposition", "attachment; filename="+name)

	// Set the content type based on your file type
	c.Set("Content-Type", fileContentType)

	// Send the file content as the response
	return c.Send(fileContent)
}

/* General */

func (g *graph) getElem(name string) (reflect.Type, bool) {
	if elem, found := g.Nodes[name]; found {
		return elem, true
	}

	if elem, found := g.Edges[name]; found {
		return elem, true
	}

	return nil, false
}

func getId(resource, key string) string {
	return resource + "/" + key
}
