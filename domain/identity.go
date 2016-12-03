package domain

import "github.com/streamtune/acl"
import "fmt"

// Identity is the concrete type for acl.Identity interface
type Identity struct {
	kind string
	id   interface{}
}

// NewIdentity will create new identity instance
func NewIdentity(kind string, id interface{}) *Identity {
	return &Identity{kind, id}
}

// GetIdentifier retrieve the identifier of the identity
func (i *Identity) GetIdentifier() interface{} {
	return i.id
}

// GetType retrieve the type of the identity
func (i *Identity) GetType() string {
	return i.kind
}

// Equals will check if this identity is equal to other one
func (i *Identity) Equals(other acl.Identity) bool {
	if o, ok := other.(*Identity); ok {
		return i.id == o.id && i.kind == o.kind
	}
	return false
}

func (i *Identity) String() string {
	return fmt.Sprintf("Identity[kind: %s, id: %s]", i.kind, i.id)
}
