package graphify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/amaury95/graphify/client"
	adminv1 "github.com/amaury95/graphify/models/domain/admin/v1"
	"github.com/amaury95/protoc-gen-graphify/interfaces"
	"github.com/arangodb/go-driver"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/fx"
	"golang.org/x/crypto/bcrypt"
)

// AdminHandler ...
type AdminHandler struct {
	config AdminHandlerConfig

	access   IAccess
	graph    IGraph
	storage  IFileStorage
	observer IObserver[Topic]
}

// AdminHandlerConfig ...
type AdminHandlerConfig struct {
	Secret []byte
}

// AdminHandlerParams ...
type AdminHandlerParams struct {
	fx.In

	Access   IAccess
	Graph    IGraph
	Storage  IFileStorage
	Observer IObserver[Topic]
}

// NewAdminHandler ...
func NewAdminHandler(config AdminHandlerConfig, params AdminHandlerParams) *AdminHandler {
	return &AdminHandler{
		config: config,

		access:   params.Access,
		graph:    params.Graph,
		storage:  params.Storage,
		observer: params.Observer,
	}
}

// Handler ...
func (e *AdminHandler) Handler(ctx context.Context) http.Handler {
	e.access.Collection(ctx, adminv1.Admin{}, func(ctx context.Context, c driver.Collection) {
		c.EnsureHashIndex(ctx, []string{"email"}, &driver.EnsureHashIndexOptions{Unique: true})
	})

	router := fiber.New(fiber.Config{
		BodyLimit: 10 << 20,
	})
	if IsDevelopmentContext(ctx) {
		router.Use(cors.New(cors.Config{
			AllowOriginsFunc: func(string) bool { return true },
			AllowCredentials: true,
		}))
	}
	router.Use(injectContext(ctx))

	admin := router.Group("/admin")
	admin.Get("/schema", e.adminSchemaHandler)
	admin.Use("/dashboard", filesystem.New(filesystem.Config{
		Root:       http.FS(client.Build),
		PathPrefix: "build",
		Browse:     true,
	}))

	auth := admin.Group("/auth")
	auth.Post("/login", e.authLoginHandler)
	auth.Post("/account", e.authRegisterHandler)
	auth.Use(e.authorized)
	auth.Post("/logout", e.authLogoutHandler)
	auth.Get("/account", e.authAccountHandler)

	files := admin.Group("/files", e.authorized)
	files.Post("/upload", e.filesUploadHandler)
	files.Get("/download/:name", e.filesDownloadHandler)

	resources := admin.Group("/:resource", e.authorized)
	resources.Get("", e.resourcesListHandler)
	resources.Post("", e.resourcesCreateHandler)
	resources.Get("/:key", e.resourcesGetHandler)
	resources.Put("/:key", e.resourcesReplaceHandler)
	resources.Delete("/:key", e.resourcesDeleteHandler)
	resources.Get("/:key/:relation", e.resourcesRelationHandler)

	// Redirect to Dashboard on NotFound
	admin.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("/admin/dashboard/")
	})
	return adaptor.FiberApp(router)
}

func injectContext(ctx context.Context) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func (e *AdminHandler) authorized(c *fiber.Ctx) error {
	// Read the JWT token from the HTTP-only cookie
	cookie := c.Cookies("jwt")
	if cookie == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "cookie not provided")
	}

	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return e.config.Secret, nil
	})
	if err != nil || !token.Valid {
		return fiber.NewError(fiber.StatusUnauthorized)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "invalid token claims")
	}

	var admin adminv1.Admin
	if err := e.access.Read(c.UserContext(), claims.Subject, &admin); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	c.SetUserContext(ContextWithAdmin(c.UserContext(), &admin))

	return c.Next()
}

/* Auth Handlers */
func (e *AdminHandler) authAccountHandler(c *fiber.Ctx) error {
	admin, found := AdminFromContext(c.UserContext())
	if !found {
		return fiber.NewError(fiber.StatusUnauthorized)
	}

	return c.JSON(&admin)
}

func (e *AdminHandler) authLoginHandler(c *fiber.Ctx) error {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	var admin adminv1.Admin
	if err := e.access.Find(c.UserContext(), map[string]interface{}{"email": request.Email}, &admin); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword(admin.PasswordHash, []byte(request.Password)); err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	expiresAt := time.Now().Add(10 * time.Hour)

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Subject:   admin.Key,
	})

	token, err := claims.SignedString(e.config.Secret)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  expiresAt,
		HTTPOnly: true,
	}
	if IsDevelopmentContext(c.UserContext()) {
		cookie.SameSite = "None"
		cookie.Secure = false
	}
	c.Cookie(&cookie)

	return c.SendStatus(fiber.StatusOK)
}

func (e *AdminHandler) authLogoutHandler(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}
	if IsDevelopmentContext(c.UserContext()) {
		cookie.SameSite = "None"
		cookie.Secure = false
	}
	c.Cookie(&cookie)
	return c.SendStatus(fiber.StatusOK)
}

func (e *AdminHandler) authRegisterHandler(c *fiber.Ctx) error {
	var request struct {
		Admin    adminv1.Admin `json:"admin"`
		Password string        `json:"password"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	if err := e.createAdmin(c.UserContext(), &request.Admin, request.Password); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.SendStatus(fiber.StatusCreated)
}

func (e *AdminHandler) createAdmin(ctx context.Context, admin *adminv1.Admin, password string) (err error) {
	if admin.PasswordHash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err != nil {
		return err
	}

	if _, err := e.access.Create(ctx, admin); err != nil {
		return err
	}

	return nil
}

/* Resource Handlers */
func (e *AdminHandler) resourcesListHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")

	elemType, found := e.restElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	bindVars := make(map[string]interface{})
	if offset, err := strconv.ParseInt(c.Query("offset"), 10, 64); err == nil {
		bindVars["offset"] = offset
	}
	if count, err := strconv.ParseInt(c.Query("count"), 10, 64); err == nil {
		bindVars["count"] = count
	}

	elems := reflect.New(reflect.SliceOf(reflect.PointerTo(elemType)))
	count, err := e.access.List(c.UserContext(), bindVars, elems.Interface())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(PaginationResult{
		Items: elems.Interface(),
		Count: count,
	})
}

func (e *AdminHandler) resourcesGetHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")

	elemType, found := e.restElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elem := reflect.New(elemType)
	if err := e.access.Read(c.UserContext(), key, elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(elem.Interface())
}

func (e *AdminHandler) resourcesCreateHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")

	elemType, found := e.restElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elem := reflect.New(elemType)
	if err := json.Unmarshal(c.Body(), elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	keys, err := e.access.Create(c.UserContext(), elem.Interface())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// emit event
	if bytes, ok := protoEncode(elem.Interface()); ok {
		admin, _ := AdminFromContext(c.UserContext())
		go e.observer.Emit(&Event[Topic]{
			Topic:     AdminCreatedTopic.For(elem.Elem().Interface()),
			Payload:   &adminv1.AdminCreatedPayload{Element: bytes, Admin: admin, Key: keys[0]},
			Timestamp: time.Now(),
		})
	}

	c.Status(fiber.StatusCreated)
	return c.JSON(keys)
}

func (e *AdminHandler) resourcesReplaceHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")

	elemType, found := e.restElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elem := reflect.New(elemType)
	if err := json.Unmarshal(c.Body(), elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	if err := e.access.Replace(c.UserContext(), key, elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// emit event
	if bytes, ok := protoEncode(elem.Interface()); ok {
		admin, _ := AdminFromContext(c.UserContext())
		go e.observer.Emit(&Event[Topic]{
			Topic:     AdminReplacedTopic.For(elem.Elem().Interface()),
			Payload:   &adminv1.AdminReplacedPayload{Element: bytes, Admin: admin},
			Timestamp: time.Now(),
		})
	}

	return c.SendStatus(fiber.StatusOK)
}

func (e *AdminHandler) resourcesDeleteHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")

	elemType, found := e.restElem(resource)
	if !found {
		return fiber.NewError(fiber.StatusNotFound)
	}

	elem := reflect.New(elemType)
	elem.Elem().FieldByName("Key").Set(reflect.ValueOf(key))
	if err := e.access.Delete(c.UserContext(), elem.Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// emit event
	admin, _ := AdminFromContext(c.UserContext())
	go e.observer.Emit(&Event[Topic]{
		Topic:     AdminDeletedTopic.For(elem.Elem().Interface()),
		Payload:   &adminv1.AdminDeletedPayload{Admin: admin, Key: key},
		Timestamp: time.Now(),
	})

	return c.SendStatus(fiber.StatusOK)
}

func (e *AdminHandler) resourcesRelationHandler(c *fiber.Ctx) error {
	resource := c.Params("resource")
	key := c.Params("key")
	collection := c.Params("relation")

	relation := e.graph.Relation(e.graph.TypeOf(collection))
	if relation == nil {
		return fiber.NewError(fiber.StatusNotFound)
	}

	edge, from, to := e.graph.TypeOf(collection), relation.From, relation.To
	if resource != e.graph.CollectionFor(from) && resource != e.graph.CollectionFor(to) {
		return fiber.NewError(fiber.StatusNotFound)
	}

	// check if the relation is inbound or outbound
	var (
		resultType reflect.Type
		direction  Direction
	)

	if resource == e.graph.CollectionFor(from) {
		resultType = reflect.StructOf([]reflect.StructField{
			{Name: "Node", Type: to, Tag: reflect.StructTag("json:\"node\"")},
			{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
		})
		direction = DirectionOutbound
	}

	if resource == e.graph.CollectionFor(to) {
		resultType = reflect.StructOf([]reflect.StructField{
			{Name: "Node", Type: from, Tag: reflect.StructTag("json:\"node\"")},
			{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
		})
		direction = DirectionInbound
	}

	elems := reflect.New(reflect.SliceOf(resultType))
	if _, err := e.access.Relations(c.UserContext(), getId(resource, key), map[string]interface{}{}, direction, elems.Interface()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(elems.Interface())

}

/* Specs Handlers */
func (e *AdminHandler) adminSchemaHandler(c *fiber.Ctx) error {
	// nodes
	nodes := map[string]interface{}{}
	for _, nodeType := range e.graph.Nodes() {
		node := reflect.New(nodeType).Interface()
		if spec, ok := node.(interfaces.Message); ok {
			nodes[e.graph.CollectionFor(nodeType)] = spec.Schema()
		}
	}

	// edges
	edges := map[string]interface{}{}
	for _, edgeType := range e.graph.Edges() {
		edge := reflect.New(edgeType).Interface()
		if spec, ok := edge.(interfaces.Message); ok {
			edges[e.graph.CollectionFor(edgeType)] = spec.Schema()
		}
	}

	// relations
	relations := map[string]map[string]string{}
	for _, edge := range e.graph.Edges() {
		relation := e.graph.Relation(edge)
		relations[e.graph.CollectionFor(edge)] = map[string]string{
			"_from": e.graph.CollectionFor(relation.From),
			"_to":   e.graph.CollectionFor(relation.To),
		}
	}

	// result
	result := map[string]interface{}{
		"nodes":     nodes,
		"edges":     edges,
		"relations": relations,
	}

	return c.JSON(result)
}

/* Files Handlers */
func (e *AdminHandler) filesUploadHandler(c *fiber.Ctx) error {

	form, err := c.MultipartForm()
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	headers, found := form.File["file"]
	if !found {
		return fiber.NewError(fiber.StatusBadRequest, "file not provided")
	}

	hashes := []string{}
	for _, header := range headers {
		file, err := header.Open()
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		hash, err := e.storage.StoreByHash(data)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		hashes = append(hashes, hash)
	}

	return c.JSON(hashes)
}

func (e *AdminHandler) filesDownloadHandler(c *fiber.Ctx) error {
	name := c.Params("name")

	fileContent, err := e.storage.ReadFile(name)
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

func (e *AdminHandler) restElem(coll string) (reflect.Type, bool) {
	exposed := map[string]reflect.Type{
		"admins": reflect.TypeOf(adminv1.Admin{}),
	}

	if elem, found := exposed[coll]; found {
		return elem, true
	}

	if elem := e.graph.TypeOf(coll); elem != nil {
		return elem, true
	}

	return nil, false
}

func getId(resource, key string) string {
	return resource + "/" + key
}

type PaginationResult struct {
	Items any   `json:"items"`
	Count int64 `json:"count"`
}

var (
	AdminCreatedTopic  Topic = "admin_created"
	AdminReplacedTopic Topic = "admin_replaced"
	AdminDeletedTopic  Topic = "admin_deleted"
)
