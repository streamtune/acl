package acl

import (
	"github.com/streamtune/acl/oid"
	"github.com/streamtune/acl/sid"
)

// Service is the interface that provides retrieval of Acl Acls.
type Service interface {
	// Locates all object identities that use the specified parent. This is useful for administration tools.
	FindChildren(oid oid.Oid) []oid.Oid

	// Reads a single ACL for the given object identity and (optionally) the list of sid.
	ReadAclById(oid oid.Oid, sids []sid.Sid) (Acl, error)

	// Obtains all the Acl that apply for the passed in object identities and (optionally) the list of sid.
	ReadAclsById(oids []oid.Oid, sids []sid.Sid) (map[oid.Oid]Acl, error)
}

// MutableService provides support for creating and storing Acl instances.
type MutableService interface {
	// Creates an empty Acl object. It will have no entries. The returnes object will then be used to add entries.
	CreateAcl(oid oid.Oid) (Acl, error)

	// Updates an existing Acl.
	UpdateAcl(acl Acl) (Acl, error)

	// Removes the specified entry from the backend storage.
	DeleteAcl(oid oid.Oid, children bool) error
}
