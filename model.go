package acl

import (
	"bytes"
	"errors"
)

// ErrSidUnloaded is returned when an Acl cannot perform an operation because the caller has requested Sid not loaded.
var (
	ErrNotFound       = errors.New("No Acl found")
	ErrExists         = errors.New("An Acl already exists for provided object identity")
	ErrChildrenExists = errors.New("Acl cannot be deleted because a children ACL exists")
	ErrSidUnloaded    = errors.New("Requested SID was not loaded")
)

// Authentication interface is used to provide authentication data.
type Authentication interface {
	GetPrincipal() string
	GetAuthorities() []string
}

// Sid is a security identity recognised by the ACL system.
//
// Thi interface provides indirection between actual security object (e.g. principals, roles, groups etc.) and what is
// stored inside an Acl. This is because an Acl will not store an entire security object, but only an abstraction of it.
// This interface therefore provides a simple way to compare these abstracted security identities with other security
// identities and actual security objects.
type Sid interface {
	// Equals will check if the provided Sid is equals to the receiver
	Equals(Sid) bool
}

// SidRetriever is a interface that provides an ability to determine the Sid Acls applicable for a given
// object.
type SidRetriever func(Authentication) []Sid

// Permission represents a permission granted to a Sid for a given domain object.
type Permission uint32

// NoPermission is used to provide no permission
// ReadPermission is used in order to read a value
// WritePermission is used in order to write a value
// CreatePermisssion is used in order to create a new value
// DeletePermission is used in order to delete a value
// AdministrationPermission is used in order to allow administration tasks
const (
	NoPermission   Permission = 0
	ReadPermission Permission = 1 << iota
	WritePermission
	CreatePermisssion
	DeletePermission
	AdministrationPermission
)

// Match will check that a permission match another one
func (p Permission) Match(other Permission) bool {
	return p&other != 0
}

// HasFlag check that a Permission hold a specific flag
func (p Permission) HasFlag(flag uint32) bool {
	return p&(1<<flag) != 0
}

// Set returns a new Permission with the provided flag set
func (p Permission) Set(flag uint32) Permission {
	return p | (1 << flag)
}

// Clear returns a new Permission with the provided flag unset
func (p Permission) Clear(flag uint32) Permission {
	return p & ^(1 << flag)
}

// Toggle returns a new Permission with the provided flag toggled
func (p Permission) Toggle(flag uint32) Permission {
	return p ^ (1 << flag)
}

// Convert a Permission to a string
func (p Permission) String() string {
	res := bytes.NewBuffer(make([]byte, 0, 32))
	for i := 0; i < 32; i++ {
		if p.HasFlag(uint32(i)) {
			res.WriteRune('*')
		} else {
			res.WriteRune('.')
		}
	}
	return res.String()
}

// AuditLogger is used in order to audit logging data.
type AuditLogger func(bool, Ace)

// PermissionGranter allow customization of the logic for determining whether a permission or permissions are
// granted to a particular Sid or Sids by an Acl.
type PermissionGranter func(Acl, []Permission, []Sid, bool, AuditLogger) (bool, error)

// Oid represents the identity of an individual domain object Acl.
type Oid interface {
	// Obtains the actual identifier. This identifier must not be reused to represent other domain objects with the same
	// type.
	//
	// Because ACLs are largely immutable, it is strongly recommended to use a synthetic identifier (such as a database
	// sequence number for the primary key). Do not use an identifier with business meaning, as that business meaning
	// may change in the future such change will cascade to the ACL subsystem data.
	GetIdentifier() interface{}

	// Obtains the "type" metadata for the domain object.
	GetType() string

	// Equals will check if the provided ObjectIdentity is equals to the receiver
	Equals(Oid) bool
}

// OidGenerator is the strategy which creates an ObjectIdentity from an object identifier (such as a primary
// key) and type information.
//
// Differs from ObjectIdentityRetrievalStrategy in that it is used in situations when the actual object Acl isn't
// available.
type OidGenerator func(interface{}, string) (Oid, error)

// OidRetriever is the interface that provides the ability to determine which ObjectIdentity will be
// returned for a particular domain object.
type OidRetriever func(interface{}) (Oid, error)

// Acl represents an access control list for a domain object.
//
// An Acl represents all ACL entries for a given domain object. In order to avoid needing references to the domain
// object itself, this interface handles indirection between a domain object and an ACL object identity via the
// ObjectIdentity.
//
// Implementing classes may elect to return Acls that represent Permission information for either some OR all Sid
// Acls. Therefore, an Acl may NOT necessarily contain ALL Sids for a given domain object.
type Acl interface {
	// Returns all of the entries represented by the present Acl. Entries associated with the Acl parents are not
	// returned.
	//
	// This method is typically used for administrative purposes.
	//
	// The order that entries apper in the array is important for methods declared in the MutableAcl interface.
	// Furthermore, some implementations MAY use ordering as part of advanced permission checking.
	//
	// Do NOT use this method for making authorization decisions. Instead use IsGranted.
	//
	// This method must operate correctly even if the Acl only represents a subset of Sids. The caller is responsible
	// for correctly handling the result if only a subset of Sids is represented.
	GetEntries() []Ace

	// Obtains the domain object this Acl provides entries for. This is immutable once an Acl is created.
	GetIdentity() Oid

	// Determines the owner of the Acl. The meaning of ownership varies by implementation and is unspecified.
	GetOwner() Sid

	// A domain object may have a prent for the purpose of ACL inheritance. If there is a parent, its ACL can be
	// accessed via this method. In turn, the parent's parent (grandparent) can be accessed and so on.
	//
	// This method solely represents the presence of a navigation hierarchy between the parent Acl and this Acl. For
	// actual inheritance to take place, the IsEntriesInheriting must also be true.
	GetParent() Acl

	// Indicates whether the ACL entries from the GetParentAcl should flow down into the current Acl.
	//
	// The mere link between an Acl and a parent Acl on its own is insufficient to cause ACL entries to inherit down.
	// This is because a domain object may wish to have entirely independent entries, but maintain the link with the
	// parent for navigation purposes. Thus, this method denotes whether or not the navigation relationship also extends
	// to the actual inheritance of entries.
	IsEntriesInheriting() bool

	// This is the actual authorization logic method, and must be used whenever ACL authorization decisions are
	// required.
	//
	// An slice of Sids are presented, representing security identifies of the current principal. In addition, a slice
	// of Permissions is presented which will have one or more bits set in order to indicate the permissions needed for
	// an affirmative authorization decision. A slice is presented because holding any of the Permissions inside the
	// slice will be sufficient for an affirmative authorization.
	//
	// The actual approach used to make authorization decisions is left to the implementation and is not specified by
	// this interface. For example, an implementation MAY search the current ACL in the order the ACL entries have been
	// stored. If a single entry is found that has the same active bits as are shown in a passed Permission, that
	// entry's grant or deny state may determine the authorization decision. If the case of a deny state, the deny
	// decision will only be relevant if all other Permissions passed in the slice have also been unsuccessfully
	// searched. If no entry is found that match the bits in the current ACL, provided that IsEntriesInheriting() is
	// true, the authorization decision may be passed to the parent ACL. If there is no matching entry, the
	// implementation MAY return an error, or make a predefined authorization decision.
	//
	// This method must operate correctly even if the Acl only represents a subset of Sids, although the implementation
	// is permitted to throw one of the signature-defined exceptions if the method is called requesting an
	// authorization decision for a Sid that was never loaded in this Acl.
	IsGranted([]Permission, []Sid, bool) (bool, error)

	// For efficiency reasons an Acl may be loaded and not contain entries for every Sid in the system.
	// If an Acl has been loaded and does not represent every Sid, all methods of the Acl can only be used within the
	// limited scope of the Sid Acls it actually represents.
	//
	// It is normal to load an Acl for only particular Sids if read-only authorization decisions are being made.
	// However, if user interface reporting or modification of Acls are desired, an Acl should be loaded with all
	// Sids. This method denotes whether or not the specified Sids have been loaded or not.
	IsSidLoaded([]Sid) bool
}

// MutableAcl represents a mutable ACL.
//
// A mutable ACL must ensure that appropriate security checks are performed before allowing access to its methods.
type MutableAcl interface {
	Acl

	// Obtains an identifier that represents this MutableAcl
	GetID() interface{}

	// Changes the present owner to a different one.
	SetOwner(Sid) error

	// Change the value returned by IsEntriesInheriting
	SetEntriesInheriting(bool) error

	// Changes the parent of this ACL.
	SetParent(Acl) error

	// Inserts a new AccessControlEntry at provided index.
	InsertAce(int, Permission, Sid, bool) error

	// Updates the permission of AccessControlEntry at provided index.
	UpdateAce(int, Permission) error

	// Deletes the AccessControlEntry at provided index.
	DeleteAce(int) error
}

// AuditableAcl is a MutableAcl that allows auditing capabilities.
type AuditableAcl interface {
	MutableAcl

	// Update auditing flags for AccessControlEntry at index
	UpdateAuditing(index int, success, failure bool) error
}

// Ace represents an individual permission assignment within an Acl.
//
// Acls MUST be immutable, as they are returned by Acl and should not allow client modification.
type Ace interface {
	// Obtains an indetifier that represents this ACE.
	GetID() interface{}

	// Retrieve the owning Acl
	GetAcl() Acl

	// Obtains the permission of this ACE
	GetPermission() Permission

	// Obtains the Sid for this ACE
	GetSid() Sid

	// Indicates the permission is being granted to the relevant Sid. If false, indicates the permission is being
	// revoked/blocked.
	IsGranting() bool
}

// AuditableAce is an AccessControlEntry that provides auditing indications
type AuditableAce interface {
	Ace

	IsAuditSuccess() bool

	IsAuditFailure() bool
}

// Cache represents a caching layer for Service.
type Cache interface {
	EvictFromCache(id interface{})

	GetFromCache(id interface{}) MutableAcl

	PutInCache(acl MutableAcl)

	ClearCache()
}

// Service is the interface that provides retrieval of Acl Acls.
type Service interface {
	// Locates all object identities that use the specified parent. This is useful for administration tools.
	FindChildren(oid Oid) []Oid

	// Reads a single ACL for the given object identity and (optionally) the list of sid.
	ReadAclById(oid Oid, sids []Sid) (Acl, error)

	// Obtains all the Acl that apply for the passed in object identities and (optionally) the list of sid.
	ReadAclsById(oids []Oid, sids []Sid) (map[Oid]Acl, error)
}

// MutableService is the interface that provides updates of Acl Acls.
type MutableService interface {
	Service

	// Creates an empty Acl object. It will have no entries. The returnes object will then be used to add entries.
	CreateAcl(oid Oid) (MutableAcl, error)

	// Updates an existing Acl.
	UpdateAcl(acl MutableAcl) (MutableAcl, error)

	// Removes the specified entry from the backend storage.
	DeleteAcl(oid Oid, children bool) error
}
