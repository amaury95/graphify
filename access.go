package graphify

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	observerv1 "github.com/amaury95/graphify/models/domain/observer/v1"
	protocgengotag "github.com/amaury95/protoc-gen-graphify/utils"
	"github.com/arangodb/go-driver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// List ...
func List(ctx context.Context, out interface{}, bindVars map[string]interface{}, conn IConnection, observer IObserver[Topic]) (int, error) {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer && outType.Elem().Kind() != reflect.Slice {
		return 0, fmt.Errorf("out must be a pointer to a slice to return the elements")
	}

	elemType := outType.Elem().Elem()
	if elemType.Kind() != reflect.Struct {
		return 0, fmt.Errorf("out elements must be struct")
	}

	db, err := conn.GetDatabase(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to establish connection: %w", err)
	}

	query := fmt.Sprintf(`FOR doc IN %s %s %s RETURN doc`, CollectionFor(elemType), getFilters(bindVars), getLimit(bindVars))

	cursor, err := db.Query(ctx, query, bindVars)
	if err != nil {
		return 0, fmt.Errorf("failed to execute query: %w", err)
	}
	defer cursor.Close()

	result := reflect.MakeSlice(reflect.SliceOf(elemType), 0, 0)
	for {
		var doc map[string]interface{}
		_, err := cursor.ReadDocument(ctx, &doc)
		if driver.IsNoMoreDocuments(err) {
			break
		} else if err != nil {
			return 0, err
		}
		elem := reflect.New(elemType)
		if loader, ok := elem.Interface().(protocgengotag.IMapLoader); ok {
			loader.LoadMap(doc)
		}
		result = reflect.Append(result, elem.Elem())
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(result)
	return 0, nil
}

// ListKeys ...
func ListKeys(ctx context.Context, keys []string, out interface{}, conn IConnection, observer IObserver[Topic]) error {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer && outType.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("out must be a pointer to a slice to return the elements")
	}

	elemType := outType.Elem().Elem()
	if elemType.Kind() != reflect.Struct {
		return fmt.Errorf("out elements must be struct")
	}

	col, err := conn.GetCollection(ctx, elemType)
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
		if loader, ok := elem.Interface().(protocgengotag.IMapLoader); ok {
			loader.LoadMap(doc)
		}
		result = reflect.Append(result, elem.Elem())
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(result)
	return nil
}

// Read ...
func Read(ctx context.Context, key string, out interface{}, conn IConnection, observer IObserver[Topic]) error {
	outType := reflect.TypeOf(out)
	if outType.Kind() != reflect.Pointer {
		return fmt.Errorf("out must be a pointer to return the element")
	}

	elemType := outType.Elem()
	if elemType.Kind() != reflect.Struct {
		return fmt.Errorf("out element must be struct")
	}

	col, err := conn.GetCollection(ctx, elemType)
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	var doc map[string]interface{}
	if _, err := col.ReadDocument(ctx, key, &doc); err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	elem := reflect.New(elemType)
	if loader, ok := elem.Interface().(protocgengotag.IMapLoader); ok {
		loader.LoadMap(doc)
	}

	outValue := reflect.ValueOf(out).Elem()
	outValue.Set(elem.Elem())

	return nil
}

// Create ...
func Create(ctx context.Context, val interface{}, conn IConnection, observer IObserver[Topic]) ([]string, error) {
	valType := reflect.TypeOf(val)

	if valType.Kind() == reflect.Slice && valType.Elem().Kind() == reflect.Struct {
		return createDocuments(ctx, val, conn, observer)
	}

	if valType.Kind() == reflect.Struct {
		return createDocument(ctx, val, conn, observer)
	}

	return nil, fmt.Errorf("val must be struct or list of struct")
}
func createDocuments(ctx context.Context, items interface{}, conn IConnection, observer IObserver[Topic]) (result []string, err error) {
	itemType := reflect.TypeOf(items).Elem()

	col, err := conn.GetCollection(ctx, itemType)
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

		if observer != nil {
			item := itemsVal.Index(index).Interface()
			if bytes, ok := protoEncode(item); ok {
				go observer.Emit(&Event[Topic]{
					Topic: CreatedTopic.For(item), Payload: &observerv1.CreatedPayload{Key: meta.Key, Element: bytes}})
			}
		}
	}

	return result, nil
}
func createDocument(ctx context.Context, item interface{}, conn IConnection, observer IObserver[Topic]) ([]string, error) {
	itemType := reflect.TypeOf(item)

	col, err := conn.GetCollection(ctx, itemType)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}

	meta, err := col.CreateDocument(ctx, item)
	if err != nil {
		return nil, fmt.Errorf("failed to insert document: %w", err)
	}

	if observer != nil {
		if bytes, ok := protoEncode(item); ok {
			go observer.Emit(&Event[Topic]{
				Topic: CreatedTopic.For(item), Payload: &observerv1.CreatedPayload{Key: meta.Key, Element: bytes}})
		}
	}

	return []string{meta.Key}, nil
}

// Update ...
func Update(ctx context.Context, key string, item interface{}, conn IConnection, observer IObserver[Topic]) error {
	itemVal := reflect.ValueOf(item)
	if itemVal.Kind() != reflect.Struct {
		return fmt.Errorf("item should be a struct")
	}

	col, err := conn.GetCollection(ctx, reflect.TypeOf(item))
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	if _, err := col.UpdateDocument(ctx, key, item); err != nil {
		return fmt.Errorf("failed to update the document")
	}

	if observer != nil {
		if bytes, ok := protoEncode(item); ok {
			go observer.Emit(&Event[Topic]{
				Topic: UpdatedTopic.For(item), Payload: &observerv1.UpdatedPayload{Element: bytes}})
		}
	}

	return nil
}

// Delete ...
func Delete(ctx context.Context, item interface{}, conn IConnection, observer IObserver[Topic]) error {
	itemVal := reflect.ValueOf(item)
	if itemVal.Kind() != reflect.Struct {
		return fmt.Errorf("item should be a struct")
	}

	keyVal := itemVal.FieldByName("Key")
	if !keyVal.IsValid() {
		return fmt.Errorf("item should have a Key")
	}

	key, ok := keyVal.Interface().(string)
	if !ok {
		return fmt.Errorf("item field Key should be string")
	}

	col, err := conn.GetCollection(ctx, reflect.TypeOf(item))
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}

	if _, err := col.RemoveDocument(ctx, key); err != nil {
		return fmt.Errorf("failed to remove the document")
	}

	if observer != nil {
		go observer.Emit(&Event[Topic]{
			Topic: DeletedTopic.For(item), Payload: &observerv1.DeletedPayload{Key: key}})
	}

	return nil
}

func protoEncode(item interface{}) ([]byte, bool) {
	message := reflect.New(reflect.TypeOf(item))
	message.Elem().Set(reflect.ValueOf(item))
	if elem, ok := message.Interface().(protoreflect.ProtoMessage); ok {
		elemBytes, _ := proto.Marshal(elem)
		return elemBytes, ok
	}
	return nil, false
}

func getLimit(bindVars map[string]interface{}) string {
	_, hasOffset := bindVars["offset"]
	_, hasCount := bindVars["count"]
	if hasOffset && hasCount {
		return "LIMIT @offset, @count"
	}
	if hasCount {
		return "LIMIT @count"
	}
	return ""
}

func getFilters(bindVars map[string]interface{}) string {
	var filters []string
	for key := range bindVars {
		if key == "count" || key == "offset" {
			continue
		}
		filters = append(filters, "doc."+key+" == @"+key)
	}
	if len(filters) > 0 {
		return "FILTER " + strings.Join(filters, " && ")
	}
	return ""
}
