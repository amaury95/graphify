package graphify

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/amaury95/graphify/client"
	accountv1 "github.com/amaury95/graphify/pkg/dashboard/domain/account/v1"
	dashboardv1 "github.com/amaury95/graphify/pkg/dashboard/domain/dashboard/v1"
	"github.com/amaury95/protoc-gen-graphify/interfaces"
	"github.com/arangodb/go-driver"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/fx"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// AdminHandler ...
type AdminHandler struct {
	config AdminHandlerConfig

	access   IAccess
	graph    IGraph
	storage  IFileStorage
	observer IObserver[Topic]

	dashboardv1.UnimplementedAuthenticationServiceServer
	dashboardv1.UnimplementedResourceServiceServer
	dashboardv1.UnimplementedSchemaServiceServer
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
func NewAdminHandler(ctx context.Context, config AdminHandlerConfig, params AdminHandlerParams) *AdminHandler {
	handler := &AdminHandler{
		config: config,

		access:   params.Access,
		graph:    params.Graph,
		storage:  params.Storage,
		observer: params.Observer,
	}

	return handler
}

func (h *AdminHandler) Handler(ctx context.Context) http.Handler {
	// ensure email index
	h.access.Collection(ctx, accountv1.Admin{}, func(ctx context.Context, c driver.Collection) {
		c.EnsureHashIndex(ctx, []string{"email"}, &driver.EnsureHashIndexOptions{Unique: true})
	})

	// Services
	server := runtime.NewServeMux(runtime.WithMiddlewares(h.authorize))
	dashboardv1.RegisterAuthenticationServiceHandlerServer(ctx, server, h)
	dashboardv1.RegisterResourceServiceHandlerServer(ctx, server, h)
	dashboardv1.RegisterSchemaServiceHandlerServer(ctx, server, h)

	// Files
	server.HandlePath("POST", "/dashboard/v1/files", h.FilesUploadHandler)
	server.HandlePath("GET", "/dashboard/v1/files/{hash}", h.FilesDownloadHandler)

	// TODO: try to use a single router

	// Router
	router := mux.NewRouter()
	router.PathPrefix("/dashboard/v1").
		Handler(server)

	// React
	build, _ := fs.Sub(client.Build, "build")
	router.PathPrefix("/dashboard").
		Handler(http.StripPrefix("/dashboard", http.FileServer(http.FS(build))))

	return router
}

func (h *AdminHandler) authorize(hf runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		// Skip authorization for dashboard/v1/login and dashboard/v1/files/{hash} routes
		skip := regexp.MustCompile(`^/dashboard/v1/(login|files/.*)$`)
		if skip.MatchString(r.URL.Path) {
			hf(w, r, pathParams)
			return
		}

		// Extract token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			http.Error(w, "Unauthorized: Invalid token format", http.StatusUnauthorized)
			return
		}

		// Parse the token
		token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(*jwt.Token) (interface{}, error) {
			return h.config.Secret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			http.Error(w, "Unauthorized: Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Retrieve admin details
		var admin accountv1.Admin
		if err := h.access.Read(r.Context(), claims.Subject, &admin); err != nil {
			http.Error(w, "Not Found: "+err.Error(), http.StatusNotFound)
			return
		}

		// Set admin context
		ctx := ContextWithAdmin(r.Context(), &admin)
		r = r.WithContext(ctx)

		// Call the next handler with pathParams
		hf(w, r, pathParams)
	}
}

func (h *AdminHandler) Login(ctx context.Context, req *dashboardv1.LoginRequest) (*dashboardv1.LoginResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	var admin accountv1.Admin
	if err := h.access.Find(ctx, Filter().WithFilter("email", req.Email), &admin); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword(admin.PasswordHash, []byte(req.Password)); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	expiresAt := time.Now().Add(10 * time.Hour)

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Subject:   admin.Key,
	})

	token, err := claims.SignedString(h.config.Secret)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &dashboardv1.LoginResponse{Token: token}, nil
}

func (h *AdminHandler) GetAccount(ctx context.Context, req *emptypb.Empty) (*dashboardv1.GetAccountResponse, error) {
	admin, _ := AdminFromContext(ctx)
	return &dashboardv1.GetAccountResponse{Admin: admin}, nil
}

func (h *AdminHandler) CreateAccount(ctx context.Context, req *dashboardv1.CreateAccountRequest) (*emptypb.Empty, error) {
	if err := h.registerAdmin(ctx, req.Admin, req.Password); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create account")
	}

	return &emptypb.Empty{}, nil
}

func (h *AdminHandler) ListResources(ctx context.Context, req *dashboardv1.ListResourcesRequest) (*dashboardv1.ListResourcesResponse, error) {
	elemType, found := h.typeOf(req.Resource)
	if !found {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	bindVars := Filter()
	if req.Offset != nil && *req.Offset > 0 {
		bindVars = bindVars.WithOffset(*req.Offset)
	}
	if req.Count != nil && *req.Count > 0 {
		bindVars = bindVars.WithCount(*req.Count)
	}

	elems := reflect.New(reflect.SliceOf(reflect.PointerTo(elemType)))
	size, err := h.access.List(ctx, bindVars, elems.Interface())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list resources")
	}

	result := Convert(elems.Elem().Len(), func(i int) *structpb.Struct {
		value, _ := structpb.NewStruct(ToMap(elems.Elem().Index(i).Interface()))
		return value
	})

	return &dashboardv1.ListResourcesResponse{Resources: result, Count: size}, nil
}

func (h *AdminHandler) GetResource(ctx context.Context, req *dashboardv1.GetResourceRequest) (*dashboardv1.GetResourceResponse, error) {
	elemType, found := h.typeOf(req.Resource)
	if !found {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	elem := reflect.New(elemType)
	if err := h.access.Read(ctx, req.Key, elem.Interface()); err != nil {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	data, err := structpb.NewStruct(ToMap(elem.Interface()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal resource")
	}

	return &dashboardv1.GetResourceResponse{Resource: data}, nil
}

func (h *AdminHandler) CreateResource(ctx context.Context, req *dashboardv1.CreateResourceRequest) (*dashboardv1.CreateResourceResponse, error) {
	elemType, found := h.typeOf(req.Resource)
	if !found {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	elem := reflect.New(elemType)
	if obj, ok := elem.Interface().(interfaces.Unmarshaler); ok {
		obj.UnmarshalMap(req.Data.AsMap())
	}

	keys, err := h.access.Create(ctx, elem.Interface())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create resource")
	}

	// emit event
	if message, ok := elem.Interface().(proto.Message); ok {
		admin, _ := AdminFromContext(ctx)
		data, _ := anypb.New(message)
		go h.observer.Emit(&Event[Topic]{
			Topic:     AdminCreatedTopic.For(elem.Elem().Interface()),
			Payload:   &accountv1.AdminCreatedPayload{Element: data, Admin: admin, Key: keys[0]},
			Timestamp: time.Now(),
		})
	}

	return &dashboardv1.CreateResourceResponse{Key: keys[0]}, nil
}

func (h *AdminHandler) UpdateResource(ctx context.Context, req *dashboardv1.UpdateResourceRequest) (*dashboardv1.UpdateResourceResponse, error) {
	elemType, found := h.typeOf(req.Resource)
	if !found {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	elem := reflect.New(elemType)
	if obj, ok := elem.Interface().(interfaces.Unmarshaler); ok {
		obj.UnmarshalMap(req.Data.AsMap())
	}

	if err := h.access.Replace(ctx, req.Key, elem.Interface()); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update resource")
	}

	// emit event
	if message, ok := elem.Interface().(proto.Message); ok {
		data, _ := anypb.New(message)
		admin, _ := AdminFromContext(ctx)
		go h.observer.Emit(&Event[Topic]{
			Topic:     AdminReplacedTopic.For(elem.Elem().Interface()),
			Payload:   &accountv1.AdminReplacedPayload{Element: data, Admin: admin},
			Timestamp: time.Now(),
		})
	}

	return &dashboardv1.UpdateResourceResponse{Resource: req.Data}, nil
}

func (h *AdminHandler) DeleteResource(ctx context.Context, req *dashboardv1.DeleteResourceRequest) (*emptypb.Empty, error) {
	elemType, found := h.typeOf(req.Resource)
	if !found {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	elem := reflect.New(elemType)
	elem.Elem().FieldByName("Key").Set(reflect.ValueOf(req.Key))
	if err := h.access.Delete(ctx, elem.Interface()); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete resource")
	}

	// emit event
	admin, _ := AdminFromContext(ctx)
	go h.observer.Emit(&Event[Topic]{
		Topic:     AdminDeletedTopic.For(elem.Elem().Interface()),
		Payload:   &accountv1.AdminDeletedPayload{Admin: admin, Key: req.Key},
		Timestamp: time.Now(),
	})

	return &emptypb.Empty{}, nil
}

func (h *AdminHandler) GetResourceRelation(ctx context.Context, req *dashboardv1.GetResourceRelationRequest) (*dashboardv1.GetResourceRelationResponse, error) {
	relation := h.graph.Relation(h.graph.TypeOf(req.Relation))
	if relation == nil {
		return nil, status.Errorf(codes.NotFound, "relation not found: %s", req.Relation)
	}

	edge, from, to := h.graph.TypeOf(req.Relation), relation.From, relation.To
	if req.Resource != h.graph.CollectionFor(from) && req.Resource != h.graph.CollectionFor(to) {
		return nil, status.Errorf(codes.NotFound, "relation not found")
	}

	// check if the relation is inbound or outbound
	var (
		resultType reflect.Type
		direction  Direction
	)

	if req.Resource == h.graph.CollectionFor(from) {
		resultType = reflect.StructOf([]reflect.StructField{
			{Name: "Node", Type: to, Tag: reflect.StructTag("json:\"node\"")},
			{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
		})
		direction = DirectionOutbound
	}

	if req.Resource == h.graph.CollectionFor(to) {
		resultType = reflect.StructOf([]reflect.StructField{
			{Name: "Node", Type: from, Tag: reflect.StructTag("json:\"node\"")},
			{Name: "Edge", Type: edge, Tag: reflect.StructTag("json:\"edge\"")},
		})
		direction = DirectionInbound
	}

	elems := reflect.New(reflect.SliceOf(resultType))
	size, err := h.access.Relations(ctx, idFor(req.Resource, req.Key), Filter(), direction, elems.Interface())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get resource relation")
	}

	result := Convert(elems.Elem().Len(), func(i int) *structpb.Struct {
		value, _ := structpb.NewStruct(ToMap(elems.Elem().Index(i).Interface()))
		return value
	})

	return &dashboardv1.GetResourceRelationResponse{Resources: result, Count: size}, nil
}

func (h *AdminHandler) GetSchema(ctx context.Context, req *emptypb.Empty) (*dashboardv1.GetSchemaResponse, error) {
	// nodes
	nodes := map[string]interface{}{}
	for _, nodeType := range h.graph.Nodes() {
		node := reflect.New(nodeType).Interface()
		if spec, ok := node.(interfaces.Message); ok {
			nodes[h.graph.CollectionFor(nodeType)] = spec.Schema()
		}
	}

	// edges
	edges := map[string]interface{}{}
	for _, edgeType := range h.graph.Edges() {
		edge := reflect.New(edgeType).Interface()
		if spec, ok := edge.(interfaces.Message); ok {
			edges[h.graph.CollectionFor(edgeType)] = spec.Schema()
		}
	}

	// relations
	relations := map[string]interface{}{}
	for _, edge := range h.graph.Edges() {
		relation := h.graph.Relation(edge)
		relations[h.graph.CollectionFor(edge)] = map[string]string{
			"_from": h.graph.CollectionFor(relation.From),
			"_to":   h.graph.CollectionFor(relation.To),
		}
	}

	schema := Pure(map[string]interface{}{
		"nodes":     nodes,
		"edges":     edges,
		"relations": relations,
	})

	data, err := structpb.NewStruct(schema)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal schema: %s", err.Error())
	}

	return &dashboardv1.GetSchemaResponse{Data: data}, nil
}

func (h *AdminHandler) FilesUploadHandler(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	// Parse the multipart form
	err := r.ParseMultipartForm(10 << 20) // Limit file size to 10 MB
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get the file headers
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		http.Error(w, "Bad Request: file not provided", http.StatusBadRequest)
		return
	}

	var hashes []string
	for _, header := range files {
		file, err := header.Open()
		if err != nil {
			http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		hash, err := h.storage.StoreByHash(data)
		if err != nil {
			http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		hashes = append(hashes, hash)
	}

	// Respond with the hashes as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hashes)
}

func (h *AdminHandler) FilesDownloadHandler(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	// Extract file hash from URL parameters
	hash, ok := pathParams["hash"]
	if !ok {
		http.Error(w, "Bad Request: Missing file hash", http.StatusBadRequest)
		return
	}

	// Read the file content
	fileContent, err := h.storage.ReadFile(hash)
	if err != nil {
		http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set content headers
	fileHeader := make([]byte, 512)
	copy(fileHeader, fileContent)
	fileContentType := http.DetectContentType(fileHeader)

	w.Header().Set("Content-Disposition", "attachment; filename="+hash)
	w.Header().Set("Content-Type", fileContentType)
	w.WriteHeader(http.StatusOK)

	// Write the file content to the response
	_, err = w.Write(fileContent)
	if err != nil {
		http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (e *AdminHandler) registerAdmin(ctx context.Context, admin *accountv1.Admin, password string) (err error) {
	if admin.PasswordHash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err != nil {
		return err
	}

	if _, err := e.access.Create(ctx, admin); err != nil {
		return err
	}

	return nil
}

func (e *AdminHandler) typeOf(name string) (reflect.Type, bool) {
	exposed := map[string]reflect.Type{
		"admins": reflect.TypeOf(accountv1.Admin{}),
	}

	if elem, found := exposed[name]; found {
		return elem, true
	}

	if elem := e.graph.TypeOf(name); elem != nil {
		return elem, true
	}

	return nil, false
}

var (
	AdminCreatedTopic  Topic = "admin_created"
	AdminReplacedTopic Topic = "admin_replaced"
	AdminDeletedTopic  Topic = "admin_deleted"
)
