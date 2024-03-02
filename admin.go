package graphify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"

	models "github.com/amaury95/graphify/models/domain/admin/v1"
	protocgengotag "github.com/amaury95/protoc-gen-go-tag/utils"
	"github.com/gorilla/mux"
	"github.com/sentimensrg/ctx/mergectx"
)

const configName = "config.json"

func (g *graph) RestHandler(ctx context.Context) http.Handler {
	g.Node(models.Admin_Account{})
	g.PrivateNode(models.Admin_Password{})
	g.AutoMigrate(ctx)

	router := mux.NewRouter()

	router.HandleFunc("/schema", g.schemaHandler).Methods(http.MethodGet)
	router.HandleFunc("/upload", g.uploadHandler).Methods("POST")
	router.HandleFunc("/download/{hash}", g.downloadHandler).Methods("GET")

	router.HandleFunc("/init", g.initHandler).Methods("POST")
	router.HandleFunc("/config", g.configHandler).Methods("GET")

	router.HandleFunc("/{resource}", g.createResourceHandler).Methods(http.MethodPost)
	router.HandleFunc("/{resource}", g.getResourcesHandler).Methods(http.MethodGet)
	router.HandleFunc("/{resource}/{key}", g.getResourceHandler).Methods(http.MethodGet)
	router.HandleFunc("/{resource}/{key}", g.updateResourceHandler).Methods(http.MethodPut)
	router.HandleFunc("/{resource}/{key}", g.deleteResourceHandler).Methods(http.MethodDelete)
	router.HandleFunc("/{resource}/{key}/{relation}", g.getRelationsHandler).Methods(http.MethodGet)

	// Middleware to inject context into each request
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(mergectx.Link(r.Context(), ctx)))
		})
	})

	return router
}

/* Rest Handlers */
func (g *graph) getResourcesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["resource"]

	elemType, found := g.getElem(name)
	if !found {
		WriteErrorResponse(w, http.StatusNotFound, errors.New("resource not found"))
		return
	}

	elems := reflect.New(reflect.SliceOf(elemType))

	keys := r.URL.Query()["key"]
	if len(keys) > 0 {
		if err := ListKeys(r.Context(), keys, elems.Interface(), g.comm); err != nil {
			WriteErrorResponse(w, http.StatusInternalServerError, err)
			return
		} else {
			WriteJSONResponse(w, http.StatusOK, elems.Interface())
			return
		}
	}

	var err error
	offset, limit := 0, 10
	if val := r.URL.Query().Get("offset"); len(val) > 0 {
		if offset, err = strconv.Atoi(val); err != nil {
			WriteErrorResponse(w, http.StatusBadRequest, err)
			return
		}
	}
	if val := r.URL.Query().Get("limit"); len(val) > 0 {
		if limit, err = strconv.Atoi(val); err != nil {
			WriteErrorResponse(w, http.StatusBadRequest, err)
			return
		}
	}

	if _, err := List(r.Context(), offset, limit, elems.Interface(), g.comm); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, elems.Interface())
}

func (g *graph) getResourceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["resource"]
	key := vars["key"]

	elemType, found := g.getElem(name)
	if !found {
		WriteErrorResponse(w, http.StatusNotFound, errors.New("resource not found"))
		return
	}

	elem := reflect.New(elemType)
	if err := Read(r.Context(), key, elem.Interface(), g.comm); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, elem.Interface())
}

func (g *graph) createResourceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["resource"]

	elemType, found := g.getElem(name)
	if !found {
		WriteErrorResponse(w, http.StatusNotFound, errors.New("resource not found"))
		return
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, err)
		return
	}

	elem := reflect.New(elemType)
	if load, ok := elem.Interface().(protocgengotag.IMapLoader); ok {
		load.LoadMap(data)
	}
	if _, err := Create(r.Context(), elem.Elem().Interface(), g.comm); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteSuccessResponse(w, http.StatusCreated)
}

func (g *graph) updateResourceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["resource"]
	key := vars["key"]

	elemType, found := g.getElem(name)
	if !found {
		WriteErrorResponse(w, http.StatusNotFound, errors.New("resource not found"))
		return
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, err)
		return
	}

	elem := reflect.New(elemType)
	if load, ok := elem.Interface().(protocgengotag.IMapLoader); ok {
		load.LoadMap(data)
	}
	if err := Update(r.Context(), key, elem.Elem().Interface(), g.comm); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteSuccessResponse(w, http.StatusCreated)
}

func (g *graph) deleteResourceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["resource"]
	key := vars["key"]

	elemType, found := g.getElem(name)
	if !found {
		WriteErrorResponse(w, http.StatusNotFound, errors.New("resource not found"))
		return
	}

	elem := reflect.New(elemType).Elem()
	elem.FieldByName("Key").Set(reflect.ValueOf(key))
	if err := Delete(r.Context(), elem.Interface(), g.comm); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteSuccessResponse(w, http.StatusCreated)
}

func (g *graph) getRelationsHandler(w http.ResponseWriter, r *http.Request) {}

/* Specs Handlers */
func (g *graph) schemaHandler(w http.ResponseWriter, r *http.Request) {
	var specs bytes.Buffer
	specs.WriteString("{")

	// nodes
	specs.WriteString("\"nodes\": {")
	for name, nodeType := range g.Nodes {
		node := reflect.New(nodeType).Interface()
		if spec, ok := node.(protocgengotag.ISchema); ok {
			specs.WriteString("\"" + name + "\":")
			specs.Write(spec.Schema())
			specs.WriteString(",")
		}
	}
	protocgengotag.TrimTrailingComma(&specs)
	specs.WriteString("},")

	// edges
	specs.WriteString("\"edges\": {")
	for name, edgeType := range g.Edges {
		edge := reflect.New(edgeType).Interface()
		if spec, ok := edge.(protocgengotag.ISchema); ok {
			specs.WriteString("\"" + name + "\":")
			specs.Write(spec.Schema())
			specs.WriteString(",")
		}
	}
	protocgengotag.TrimTrailingComma(&specs)
	specs.WriteString("},")

	specs.WriteString("\"relations\": {")
	for from, edges := range g.Relations {
		specs.WriteString("\"" + from + "\": {")
		for to, edge := range edges {
			specs.WriteString("\"" + to + "\":\"" + edge + "\",")
		}
		protocgengotag.TrimTrailingComma(&specs)
		specs.WriteString("},")
	}
	protocgengotag.TrimTrailingComma(&specs)
	specs.WriteString("}")

	specs.WriteString("}")

	WriteResponse(w, http.StatusOK, specs.Bytes())
}

/* Config Handlers */
func (g *graph) initHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := g.comm.Storage.ReadFile(configName); err == nil {
		WriteErrorResponse(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	var request ApplicationConfigInit
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, err)
		return
	}

	// TODO: register admin

	cnf, _ := json.Marshal(request.Config)
	if err := g.comm.Storage.StoreFile(configName, cnf); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteSuccessResponse(w, http.StatusOK)
}

func (g *graph) configHandler(w http.ResponseWriter, r *http.Request) {
	conf, err := g.comm.Storage.ReadFile(configName)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, err)
		return
	}

	WriteResponse(w, http.StatusOK, conf)
}

/* Files Handlers */
func (g *graph) uploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(g.comm.Storage.MaxMemory())
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, err)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()

	hash, err := g.comm.Storage.StoreByHash(file)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	WriteJSONResponse(w, http.StatusCreated, map[string]string{"hash": hash})
}

func (g *graph) downloadHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileHash := vars["hash"]

	fileContent, err := g.comm.Storage.ReadFile(fileHash)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	// Set the Content-Type header based on the file type or use application/octet-stream
	fileHeader := make([]byte, 512)
	copy(fileHeader, fileContent)
	fileContentType := http.DetectContentType(fileHeader)

	WriteFileResponse(w, fileHash, fileContentType, fileContent)
}

/* Utils */
func WriteResponse(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

func WriteJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(dataBytes)
}

func WriteSuccessResponse(w http.ResponseWriter, status int) {
	WriteJSONResponse(w, status, map[string]bool{"success": true})
}

func WriteFileResponse(w http.ResponseWriter, filename, fileContentType string, fileContent []byte) {
	// Set the Content-Disposition header to make the browser display the file download dialog
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", fileContentType)

	// Write the file content to the response
	w.Write(fileContent)
}

func WriteErrorResponse(w http.ResponseWriter, status int, err error) {
	http.Error(w, err.Error(), status)
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
