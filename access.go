package graphify

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	observerv1 "github.com/amaury95/graphify/pkg/models/domain/observer/v1"
	"github.com/amaury95/protoc-gen-graphify/interfaces"
	"github.com/arangodb/go-driver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// CollectionCallback ...
type CollectionCallback func(context.Context, driver.Collection)

// IAccess ...
type IAccess interface {
	// AutoMigrate ...
	AutoMigrate(ctx context.Context, graph IGraph) error

	// Collection ...
	Collection(ctx context.Context, elem any, callbacks ...CollectionCallback) (err error)

	// List ...
	List(ctx context.Context, bindVars IVars, out any) (int64, error)

	// ListKeys ...
	ListKeys(ctx context.Context, keys []string, out any) error

	// Find ...
	Find(ctx context.Context, bindVars IVars, out any) error

	// Read ...
	Read(ctx context.Context, key string, out any) error

	// Create ...
	Create(ctx context.Context, val any) ([]string, error)

	// Update ...
	Update(ctx context.Context, key string, item any) error

	// Replace ...
	Replace(ctx context.Context, key string, item any) error

	// Delete ...
	Delete(ctx context.Context, item any) error

	// Relations ...
	Relations(ctx context.Context, id string, bindVars IVars, direction Direction, out any) (int, error)
}

type ArangoAccess struct {
	conn     IConnection
	observer IObserver[Topic]
}

func NewArangoAccess(conn IConnection, observer IObserver[Topic]) *ArangoAccess {
	return &ArangoAccess{conn: conn, observer: observer}
}

// typecheck for arango access
var _ IAccess = new(ArangoAccess)

// AutoMigrate ...
func (e *ArangoAccess) AutoMigrate(ctx context.Context, graph IGraph) error {
	for _, node := range graph.Nodes() {
		node := reflect.New(node).Elem()
		if err := e.Collection(ctx, node.Interface()); err != nil {
			return err
		}
	}
	for _, edge := range graph.Edges() {
		edge := reflect.New(edge).Elem()
		if err := e.Collection(ctx, edge.Interface()); err != nil {
			return err
		}
	}
	return nil
}

// Collection ...
func (e *ArangoAccess) Collection(ctx context.Context, elem any, callbacks ...CollectionCallback) (err error) {
	elemType := reflect.TypeOf(elem)
	elemName := collectionFor(elemType)

	db, err := e.conn.Database(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	var col driver.Collection
	if isEdge(elemType) {
		if col, err = createEdgeCollection(ctx, elemName, db); err != nil {
			return err
		}
	} else if isNode(elemType) {
		if col, err = createNodeCollection(ctx, elemName, db); err != nil {
			return err
		}
	} else {
		return errors.New("migrate only nodes or edges")
	}

	for _, callback := range callbacks {
		callback(ctx, col)
	}

	return nil
}

func createNodeCollection(ctx context.Context, name string, db driver.Database) (col driver.Collection, err error) {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		if col, err = db.CreateCollection(ctx, name, nil); err != nil {
			return nil, fmt.Errorf("failed to create collection: %w", err)
		}
		return
	}

	return db.Collection(ctx, name)
}

func createEdgeCollection(ctx context.Context, name string, db driver.Database) (col driver.Collection, err error) {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to check collection existence: %w", err)
	}

	if !exists {
		if col, err = db.CreateCollection(ctx, name, &driver.CreateCollectionOptions{Type: driver.CollectionTypeEdge}); err != nil {
			return nil, fmt.Errorf("failed to create collection: %w", err)
		}
		return
	}

	return db.Collection(ctx, name)
}

// List ...
func (e *ArangoAccess) List(ctx context.Context, bindVars IVars, out any) (int64, error) {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer && outType.Elem().Kind() != reflect.Slice {
		return -1, fmt.Errorf("out must be a pointer to a slice to return the elements")
	}

	elemType := outType.Elem().Elem()
	if elemType.Kind() != reflect.Pointer && elemType.Elem().Kind() != reflect.Struct {
		return -1, fmt.Errorf("out elements must be pointers to struct")
	}

	collection, err := e.conn.Reflect(ctx, elemType.Elem())
	if err != nil {
		return -1, fmt.Errorf("failed tp load collection: %w", err)
	}
	count, err := collection.Count(ctx)
	if err != nil {
		return -1, err
	}

	db, err := e.conn.Database(ctx)
	if err != nil {
		return -1, fmt.Errorf("failed to establish connection: %w", err)
	}

	query := fmt.Sprintf(`FOR doc IN %s %s %s RETURN doc`,
		collectionFor(elemType.Elem()), bindVars.Filters(), bindVars.Limit())

	cursor, err := db.Query(ctx, query, bindVars.Values())
	if err != nil {
		return -1, fmt.Errorf("failed to execute query: %w", err)
	}
	defer cursor.Close()

	result := reflect.MakeSlice(reflect.SliceOf(elemType), 0, 0)
	for {
		elem := reflect.New(elemType.Elem())
		if _, err := cursor.ReadDocument(ctx, elem.Interface()); driver.IsNoMoreDocuments(err) {
			break
		} else if err != nil {
			return -1, fmt.Errorf("failed to read document: %w", err)
		}
		result = reflect.Append(result, elem)
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(result)
	return count, nil
}

// ListKeys ...
func (e *ArangoAccess) ListKeys(ctx context.Context, keys []string, out any) error {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer && outType.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("out must be a pointer to a slice to return the elements")
	}

	elemType := outType.Elem().Elem()
	if elemType.Kind() != reflect.Struct {
		return fmt.Errorf("out elements must be struct")
	}

	col, err := e.conn.Reflect(ctx, elemType)
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	docs := make([]map[string]interface{}, len(keys))
	_, errors, err := col.ReadDocuments(ctx, keys, docs)
	if err != nil {
		return fmt.Errorf("failed to read documents: %w", err)
	}
	if err := errors.FirstNonNil(); err != nil {
		return fmt.Errorf("failed to read documents: %w", err)
	}

	result := reflect.MakeSlice(reflect.SliceOf(elemType), 0, len(keys))
	for _, doc := range docs {
		elem := reflect.New(elemType)
		if loader, ok := elem.Interface().(interfaces.Unmarshaler); ok {
			loader.UnmarshalMap(doc)
		}
		result = reflect.Append(result, elem.Elem())
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(result)
	return nil
}

// Find ...
func (e *ArangoAccess) Find(ctx context.Context, bindVars IVars, out any) error {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer {
		return fmt.Errorf("out must be a pointer to return the element")
	}

	elemType := outType.Elem()
	if elemType.Kind() != reflect.Struct {
		return fmt.Errorf("out element must be struct")
	}

	db, err := e.conn.Database(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	query := fmt.Sprintf(`FOR doc IN %s %s LIMIT 1 RETURN doc`,
		collectionFor(elemType), bindVars.Filters())

	cursor, err := db.Query(ctx, query, bindVars.Values())
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}
	defer cursor.Close()

	if _, err := cursor.ReadDocument(ctx, out); err != nil {
		return fmt.Errorf("failed to read document: %w", err)
	}

	return nil
}

// Read ...
func (e *ArangoAccess) Read(ctx context.Context, key string, out any) error {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer {
		return fmt.Errorf("out must be a pointer to return the element")
	}

	elemType := outType.Elem()
	if elemType.Kind() != reflect.Struct {
		return fmt.Errorf("out element must be struct")
	}

	col, err := e.conn.Reflect(ctx, elemType)
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	var doc map[string]interface{}
	if _, err := col.ReadDocument(ctx, key, &doc); err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	elem := reflect.New(elemType)
	if loader, ok := elem.Interface().(interfaces.Unmarshaler); ok {
		loader.UnmarshalMap(doc)
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(elem.Elem())

	return nil
}

// Create ...
func (e *ArangoAccess) Create(ctx context.Context, val any) ([]string, error) {
	valType := reflect.TypeOf(val)

	if valType.Kind() == reflect.Slice && valType.Elem().Kind() == reflect.Struct {
		return e.createDocuments(ctx, val)
	}

	if valType.Kind() == reflect.Pointer && valType.Elem().Kind() == reflect.Struct {
		return e.createDocument(ctx, val)
	}

	return nil, fmt.Errorf("val must be struct or list of struct")
}
func (e *ArangoAccess) createDocuments(ctx context.Context, items any) (result []string, err error) {
	itemType := reflect.TypeOf(items).Elem()

	col, err := e.conn.Reflect(ctx, itemType)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}

	meta, errors, err := col.CreateDocuments(ctx, items)
	if err != nil {
		return nil, fmt.Errorf("failed to insert document: %w", err)
	}

	if err := errors.FirstNonNil(); err != nil {
		return nil, fmt.Errorf("failed to insert document: %w", err)
	}

	itemsVal := reflect.ValueOf(items)
	for index, meta := range meta {
		result = append(result, meta.Key)

		// emit events
		item := itemsVal.Index(index).Interface()
		if bytes, ok := protoEncode(item); ok {
			go e.observer.Emit(&Event[Topic]{
				Topic:     CreatedTopic.For(item),
				Payload:   &observerv1.CreatedPayload{Key: meta.Key, Element: bytes},
				Timestamp: time.Now(),
			})
		}

	}

	return result, nil
}
func (e *ArangoAccess) createDocument(ctx context.Context, item any) ([]string, error) {
	itemType := reflect.TypeOf(item).Elem()

	col, err := e.conn.Reflect(ctx, itemType)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}

	meta, err := col.CreateDocument(ctx, item)
	if err != nil {
		return nil, fmt.Errorf("failed to insert document: %w", err)
	}

	// emit event
	if bytes, ok := protoEncode(item); ok {
		go e.observer.Emit(&Event[Topic]{
			Topic:     CreatedTopic.For(item),
			Payload:   &observerv1.CreatedPayload{Key: meta.Key, Element: bytes},
			Timestamp: time.Now(),
		})
	}

	return []string{meta.Key}, nil
}

// Update ...
func (e *ArangoAccess) Update(ctx context.Context, key string, item any) error {
	itemVal := reflect.ValueOf(item)
	if itemVal.Kind() != reflect.Pointer || itemVal.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("item should be a pointer to struct")
	}

	col, err := e.conn.Reflect(ctx, reflect.TypeOf(item).Elem())
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	if _, err := col.UpdateDocument(ctx, key, item); err != nil {
		return fmt.Errorf("failed to update the document")
	}

	// emit event
	if bytes, ok := protoEncode(item); ok {
		go e.observer.Emit(&Event[Topic]{
			Topic:     UpdatedTopic.For(item),
			Payload:   &observerv1.UpdatedPayload{Element: bytes},
			Timestamp: time.Now(),
		})
	}

	return nil
}

// Replace ...
func (e *ArangoAccess) Replace(ctx context.Context, key string, item any) error {
	itemVal := reflect.ValueOf(item)
	if itemVal.Kind() != reflect.Pointer || itemVal.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("item should be a pointer to struct")
	}

	col, err := e.conn.Reflect(ctx, reflect.TypeOf(item).Elem())
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	if _, err := col.ReplaceDocument(ctx, key, item); err != nil {
		return fmt.Errorf("failed to replace the document")
	}

	// emit event
	if bytes, ok := protoEncode(item); ok {
		go e.observer.Emit(&Event[Topic]{
			Topic:     ReplacedTopic.For(item),
			Payload:   &observerv1.ReplacedPayload{Element: bytes},
			Timestamp: time.Now(),
		})
	}

	return nil
}

// Delete ...
func (e *ArangoAccess) Delete(ctx context.Context, item any) error {
	itemVal := reflect.ValueOf(item)
	if itemVal.Kind() != reflect.Pointer || itemVal.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("item should be a pointer to struct")
	}

	keyVal := itemVal.Elem().FieldByName("Key")
	if !keyVal.IsValid() {
		return fmt.Errorf("item should have a Key")
	}

	key, ok := keyVal.Interface().(string)
	if !ok {
		return fmt.Errorf("item field Key should be string")
	}

	col, err := e.conn.Reflect(ctx, itemVal.Elem().Type())
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	if _, err := col.RemoveDocument(ctx, key); err != nil {
		return fmt.Errorf("failed to remove the document")
	}

	// emit event
	go e.observer.Emit(&Event[Topic]{
		Topic:     DeletedTopic.For(item),
		Payload:   &observerv1.DeletedPayload{Key: key},
		Timestamp: time.Now(),
	})

	return nil
}

type Direction string

const (
	DirectionInbound  Direction = "INBOUND"
	DirectionOutbound Direction = "OUTBOUND"
	DirectionAny      Direction = "ANY"
)

// Relations ...
func (e *ArangoAccess) Relations(ctx context.Context, id string, bindVars IVars, direction Direction, out any) (int, error) {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer && outType.Elem().Kind() != reflect.Slice {
		return -1, fmt.Errorf("out must be a pointer to a slice to return the elements")
	}

	elemType := outType.Elem().Elem()
	if elemType.Kind() != reflect.Struct {
		return -1, fmt.Errorf("out elements must be struct")
	}

	if elemType.NumField() != 2 {
		return -1, fmt.Errorf("out must have exactly two fields")
	}

	nodeField, foundNode := elemType.FieldByName("Node")
	if !foundNode || !isNode(nodeField.Type) {
		return -1, fmt.Errorf("node not present in result or is invalid")
	}

	edgeField, foundEdge := elemType.FieldByName("Edge")
	if !foundEdge || !isEdge(edgeField.Type) {
		return -1, fmt.Errorf("edge not present in result or is invalid")
	}

	db, err := e.conn.Database(ctx)
	if err != nil {
		return -1, fmt.Errorf("failed to establish connection: %w", err)
	}

	query := fmt.Sprintf(`FOR node, edge IN 1..1 %s '%s' %s %s %s RETURN {node, edge}`,
		string(direction), id, collectionFor(edgeField.Type), bindVars.Filters(), bindVars.Limit())

	cursor, err := db.Query(ctx, query, bindVars.Values())
	if err != nil {
		return -1, fmt.Errorf("failed to execute query: %w", err)
	}
	defer cursor.Close()

	result := reflect.MakeSlice(outType.Elem(), 0, 0)
	for {
		value := reflect.New(elemType)
		_, err := cursor.ReadDocument(ctx, value.Interface())
		if driver.IsNoMoreDocuments(err) {
			break
		} else if err != nil {
			return -1, err
		}
		result = reflect.Append(result, value.Elem())
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(result)
	return 0, nil // TODO: finish return total count
}

// protoEncode ...
func protoEncode(item any) ([]byte, bool) {
	message := reflect.New(reflect.TypeOf(item))
	message.Elem().Set(reflect.ValueOf(item))
	if elem, ok := message.Interface().(protoreflect.ProtoMessage); ok {
		elemBytes, _ := proto.Marshal(elem)
		return elemBytes, ok
	}
	return nil, false
}

var (
	CreatedTopic  Topic = "created"
	UpdatedTopic  Topic = "updated"
	ReplacedTopic Topic = "replaced"
	DeletedTopic  Topic = "deleted"
)
