package objectIdentity

import (
	"errors"
	"fmt"
	"reflect"
)

// Oid is the object identity
type Oid struct {
	kind string
	id   interface{}
}

// New will create new identity instance
func New(kind string, id interface{}) (*Oid, error) {
	if id == nil || kind == "" {
		return nil, errors.New("Invalid kind or id provided.")
	}
	return &Oid{kind, id}, nil
}

type idGetter interface {
	GetID() interface{}
}

// NewFrom will create a new Oid by the object instance.
func NewFrom(object interface{}) (*Oid, error) {
	objType := reflect.TypeOf(object)
	kind := objType.Name()
	if getter, ok := object.(idGetter); ok {
		id := getter.GetID()
		return New(kind, id)
	}
	// Check for a property named ID
	val := reflect.ValueOf(object).FieldByName("ID")
	if val.CanInterface() {
		return New(kind, val.Interface())
	}
	return nil, fmt.Errorf("Object %x does not provide a GetID method", object)
}
