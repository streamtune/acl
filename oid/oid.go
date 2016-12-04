package oid

import (
	"errors"
	"fmt"
	"reflect"
)

// DefaultGenerator is the default Generator interface implementation
var DefaultGenerator Generator

// DefaultRetriever is the default Retriever interface implementation
var DefaultRetriever Retriever

func init() {
	DefaultGenerator = new(objectIdentityGenerator)
	DefaultRetriever = new(objectIdentityRetriever)
}

// Oid represents the identity of an individual domain object instance.
//
// As implementations of Oid are used as the key to represent domain objects in the ACL subsystem, it is essential that
// implementations provide methods so that object-equality rather than reference-equality can be relied upon reliably.
// In other words, the ACL subsystem can consider two Oids equal if oid1.Equals(oid2), rather than reference-equality of
// oid1==oid2
type Oid interface {
	// Equals test the receiver for equality with this one.
	Equals(Oid) bool

	// Obtains the actual identifier. This identifier must not be reused to represent other domain objects with the same
	// type.
	//
	// Because ACLs are largely immutable, it is strongly recommended to use a synthetic identifier (such as a database
	// sequence number for the primary key). Do not use an identifier with business meaning, as that business meaning
	// may change in the future such change will cascade to the ACL subsystem data.
	Identifier() interface{}

	// Obtains the "type" metadata for the domain object. This will often be a go type name (an interface or a class).
	// Traditionally it is the name of the domain object implementation class.
	Type() string
}

// Generator is a strategy which creates an Oid from an object identifier (such as a primary key) and type information.
//
// Differs from Retriever in that it is used in situations when the actual object instance isn't available.
type Generator interface {
	Generate(id interface{}, kind string) (Oid, error)
}

// Retriever is a strategy interface that provides the ability to determine which Oid will be returned for a particular
// domain object
type Retriever interface {
	Retrieve(object interface{}) (Oid, error)
}

type objectIdentity struct {
	kind string
	id   interface{}
}

func (id *objectIdentity) Equals(other Oid) bool {
	if othID, ok := other.(*objectIdentity); ok {
		return id.kind == othID.kind && id.id == othID.id
	}
	return false
}

func (id *objectIdentity) Identifier() interface{} {
	return id.id
}

func (id *objectIdentity) Type() string {
	return id.kind
}

func (id *objectIdentity) String() string {
	return fmt.Sprintf("ObjectIdentity[kind=%s,id=%s]", id.kind, id.id)
}

type objectIdentityGenerator struct{}

func (g *objectIdentityGenerator) Generate(id interface{}, kind string) (Oid, error) {
	if kind == "" {
		return nil, errors.New("Cannot create Oid with empty kind")
	}
	if id == nil {
		return nil, errors.New("Cannot create Oid from nil id")
	}
	return &objectIdentity{kind, id}, nil
}

// Generate a new Oid from given id and kind
func Generate(id interface{}, kind string) (Oid, error) {
	return DefaultGenerator.Generate(id, kind)
}

type objectIdentityRetriever struct{}

func (r *objectIdentityRetriever) Retrieve(object interface{}) (Oid, error) {
	type idGetter interface {
		GetID() interface{}
	}

	if object == nil {
		return nil, errors.New("Cannot create Oid from nil object")
	}
	kind := reflect.TypeOf(object).Name()
	if getter, ok := object.(idGetter); ok {
		return &objectIdentity{kind, getter.GetID()}, nil
	}
	if val := reflect.ValueOf(object).FieldByName("ID"); val.CanInterface() {
		return &objectIdentity{kind, val.Interface()}, nil
	}
	return nil, fmt.Errorf("Object %s does not provide a GetID method or ID field", object)
}

// Retrieve a new Oid from provided object
func Retrieve(object interface{}) (Oid, error) {
	return DefaultRetriever.Retrieve(object)
}
