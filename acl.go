package acl

import (
	"context"
	"errors"
	"fmt"

	"github.com/lib/pq/oid"
	"github.com/streamtune/acl/change"
	"github.com/streamtune/acl/permission"
	"github.com/streamtune/acl/sid"
)

// Acl represents an access control list (ACL) for a domain object.
//
// An Acl represents all ACL entries for a given domain object. In order to avoid needing references to the domain
// object itself, this interface handles indirection between a domain object and an ACL object identity via the oid.Oid
// interface.
//
// Implementing classes may elect to return instances that represent permission.Permission information for either some
// OR all sid.Sid instances. Therefore, an instance may NOT necessarily contain ALL sid.Sid  for a given domain object.
type Acl interface {
	// Entries returns all of the entries represented by the present Acl. Entries associated with the Acl parents are
	// not returned.
	// This method is typically used for administrative purposes.
	//
	// The order that entries appear in the array is important for methods declared in the MutableAcl interface.
	// Furthermore, some implementations MAY use ordering as part of advanced permission checking.
	//
	// Do NOT use this method for making authorization decisions. Instead use IsGranted.
	//
	// This method must operate correctly even if the Acl only represents a subset of Sids. The caller is responsible
	// for correctly handling the result if only a subset of Sids is represented.
	GetEntries() []Ace

	// Obtains the domain object this Acl provides entries for. This is immutable once an Acl is created.
	GetIdentity() oid.Oid

	// Determines the owner of the Acl. The meaning of ownership varies by implementation and is unspecified.
	GetOwner() sid.Sid

	// A domain object may have a parent for the purpose of ACL inheritance. If there is a parent, its ACL can be
	// accessed via this method. In turn, the parent's parent (grandparent) can be accessed and so on.
	//
	// This method solely represents the presence of a navigation hierarchy between the parent Acl and this Acl. For
	// actual inheritance to take place, the EntriesInheriting must also be true.
	//
	// This method must operate correctly even if the Acl only represents a subset of Sids. The caller is responsible
	// for correctly handling the result if only a subset of Sids is represented.
	GetParent() Acl

	// Indicates whether the ACL entries from the Parent() should flow down into the current Acl.
	//
	// The mere link between an Acl and a parent Acl on its own is insufficient to cause ACL entries to inherit down.
	// This is because a domain object may wish to have entirely independent entries, but maintain the link with the
	// parent for navigation purposes. Thus, this method denotes whether or not the navigation relationship also extends
	// to the actual inheritance of entries.
	IsEntriesInheriting() bool

	// This is the actual authorization logic method, and must be used whenever ACL authorization decisions are
	// required.
	//
	// A slice of Sids are presented, representing security identifies of the current principal. In addition, a slice of
	// Permissions is presented which will have one or more bits set in order to indicate the permissions needed for an
	// affirmative authorization decision. A slice is presented because holding any of the Permissions inside the slice
	// will be sufficient for an affirmative authorization.
	//
	// The actual approach used to make authorization decisions is left to the implementation and is not specified by
	// this interface. For example, an implementation MAY search the current ACL in the order the ACL entries have been
	// stored. If a single entry is found that has the same active bits as are shown in a passed Permission, that
	// entry's grant or deny state may determine the authorization decision. If the case of a deny state, the deny
	// decision will only be relevant if all other Permissions passed in the slice have also been unsuccessfully
	// searched. If no entry is found that match the bits in the current ACL, provided that EntriesInheriting() is true,
	// the authorization decision may be passed to the parent ACL. If there is no matching entry, the implementation MAY
	// throw an exception, or make a predefined authorization decision.
	//
	// This method must operate correctly even if the Acl only represents a subset of Sids. The caller is responsible
	// for correctly handling the result if only a subset of Sids is represented.
	IsGranted(permissions []permission.Permission, sids []sid.Sid, admin bool) (bool, error)

	// For efficiency reasons an Acl may be loaded and not contain entries for every Sid in the system. If an Acl has
	// been loaded and does not represent every Sid, all methods of the Acl can only be used within the limited scope of
	// the Sid instances it actually represents.
	//
	// It is normal to load an Acl for only particular Sids if read-only authorization decisions are being made.
	// However, if user interface reporting or modification of Acls are desired, an Acl should be loaded with all Sids.
	// This method denotes whether or not the specified Sids have been loaded or not.
	IsSidLoaded([]sid.Sid) bool
}

// MutableAcl is the interface exposting the mutator methods for an Acl
type MutableAcl interface {
	Acl

	// Obtains an indetifier that represents this MutableAcl.
	GetID() interface{}

	// Changes the current owner to a different one
	SetOwner(context.Context, sid.Sid) error

	// Changes the value of entries inherits
	SetEntriesInhriting(context.Context, bool) error

	// Change the parent object
	SetParent(context.Context, Acl) error

	// Insert a new Ace to this ACL
	InsertAce(context.Context, int, permission.Permission, sid.Sid, bool) error

	// Updates an existing Ace
	UpdateAce(context.Context, int, permission.Permission) error

	// Deletes an existing Ace
	DeleteAce(context.Context, int) error
}

// AuditableAcl is the interface exposting auditing mutator methods.
type AuditableAcl interface {
	MutableAcl

	// Update auditing informations of an entry
	UpdateAuditing(context.Context, int, bool, bool)
}

type acl struct {
	id         interface{}
	oid        oid.Oid
	owner      sid.Sid
	parent     Acl
	authorizer Authorizer
	checker    Checker
	aces       []Ace
	inherits   bool
	loaded     []sid.Sid
}

func newAcl(id interface{}, oid oid.Oid, auth Authorizer, checker Checker, parent Acl, loaded []sid.Sid, inherits bool, owner sid.Sid) (*acl, error) {
	if auth == nil {
		return nil, errors.New("Authorizer must not be null")
	}
	if checker == nil {
		return nil, errors.New("Permission checker must not be null")
	}
	return &acl{
		id:         id,
		oid:        oid,
		owner:      owner,
		parent:     parent,
		authorizer: auth,
		checker:    checker,
		inherits:   inherits,
		loaded:     loaded,
	}, nil
}

func (acl *acl) verifyIndexExists(index int) error {
	if index < 0 {
		return errors.New("index must be greater thant or equal to zero")
	}
	if index >= len(acl.aces) {
		return fmt.Errorf("index must refer to an index of Ace list. List size is %d, index was %d", len(acl.aces), index)
	}
	return nil
}

// InsertAce will create and insert a new Ace.
func (acl *acl) InsertAce(ctx context.Context, index int, permission permission.Permission, sid sid.Sid, granting bool) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.General); err != nil {
		return err
	}
	if index < 0 || index > len(acl.aces) {
		return errors.New("Invalid index for ACE creation")
	}
	ace := newAccessControlEntry(nil, acl, sid, permission, granting, false, false)
	acl.aces = append(acl.aces[:index], append([]Ace{ace}, acl.aces[index:]...)...)
	return nil
}

// UpdateAce will update an existing Ace
func (acl *acl) UpdateAce(ctx context.Context, index int, permission permission.Permission) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.General); err != nil {
		return err
	}
	if err := acl.verifyIndexExists(index); err != nil {
		return err
	}
	ace, _ := acl.aces[index].(*accessControlEntry)
	ace.setPermission(permission)
	return nil
}

// DeleteAce will delete the Ace at provided index
func (acl *acl) DeleteAce(ctx context.Context, index int) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.General); err != nil {
		return err
	}
	if err := acl.verifyIndexExists(index); err != nil {
		return err
	}
	acl.aces = append(acl.aces[:index], acl.aces[index+1:]...)
	return nil
}

// GetEntries will retrieve all the entries
func (acl *acl) GetEntries() []Ace {
	result := make([]Ace, len(acl.aces))
	copy(result, acl.aces)
	return result
}

// GetID will retrieve the unique object id
func (acl *acl) GetID() interface{} {
	return acl.id
}

// GetIdentity will retrieve the object identity
func (acl *acl) GetIdentity() oid.Oid {
	return acl.oid
}

// IsEntriesInheriting will check if this acl object inherits
func (acl *acl) IsEntriesInheriting() bool {
	return acl.inherits
}

// IsGranted delegates to Granter
func (acl *acl) IsGranted(permissions []permission.Permission, sids []sid.Sid, admin bool) (bool, error) {
	if !acl.IsSidLoaded(sids) {
		return false, errors.New("No all the requested Sid where loaded.")
	}
	return acl.checker.Check(acl, permissions, sids, admin)
}

// IsSidLoaded check if all the provided Sids are laoded
func (acl *acl) IsSidLoaded(sids []sid.Sid) bool {
	// If loaded is nul, this indicates all SIDs were loaded. Also return true if the callre didn't specify a SID
	if acl.loaded == nil || sids == nil || len(sids) == 0 {
		return true
	}
	// This ACL applies to a SID subset only. Iterate to check if applies.
	for _, sid := range sids {
		found := false
		for _, loaded := range acl.loaded {
			if sid.Equals(loaded) {
				// This SID is OK
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// SetEntriesInheriting will change the value of inheritance flag
func (acl *acl) SetEntriesInheriting(ctx context.Context, entriesInheriting bool) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.General); err != nil {
		return err
	}
	acl.inherits = entriesInheriting
	return nil
}

// SetOwner will change the owner.
func (acl *acl) SetOwner(ctx context.Context, newOwner sid.Sid) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.Ownership); err != nil {
		return err
	}
	acl.owner = newOwner
	return nil
}

// GetOwner will retrieve the owner.
func (acl *acl) GetOwner() sid.Sid {
	return acl.owner
}

// SetParent will change the perant of this acl.
func (acl *acl) SetParent(ctx context.Context, newParent Acl) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.General); err != nil {
		return err
	}
	if newParent != nil && acl == newParent {
		return errors.New("Cannot be the parent of yourself")
	}
	acl.parent = newParent
	return nil
}

// GetParent will retrieve the parent ACL
func (acl *acl) GetParent() Acl {
	return acl.parent
}

// UpdateAuditing will udpate the auditing entries for ACE in provided index
func (acl *acl) UpdateAuditing(ctx context.Context, index int, succes, failure bool) error {
	if err := acl.authorizer.Authorize(ctx, acl, change.Auditing); err != nil {
		return err
	}
	if err := acl.verifyIndexExists(index); err != nil {
		return err
	}
	ace, _ := acl.aces[index].(*accessControlEntry)
	ace.setAuditSuccess(succes)
	ace.setAuditFailure(failure)
	return nil
}

// Ace represents an individual permission assignment within an Acl.
//
// Instances MUST be immutable, as they are returned by Acl and should not allow client modification.
type Ace interface {
	// Retrieve the owner Acl
	GetAcl() Acl

	// Obtains an identifier that represents this ACE.
	GetID() interface{}

	// Obtains the permission for this ace
	GetPermission() permission.Permission

	// Obtains the Sid for this ace
	GetSid() sid.Sid

	// Indicates the permission is being granted to the relevant Sid. If false, indicates the permission is being
	// revoked/blocked.
	IsGranting() bool
}

type accessControlEntry struct {
	id         interface{}
	acl        Acl
	permission permission.Permission
	sid        sid.Sid
	granting   bool
	succes     bool
	failure    bool
}

func newAccessControlEntry(id interface{}, acl Acl, sid sid.Sid, permission permission.Permission, granting, success, failure bool) *accessControlEntry {
	return &accessControlEntry{id, acl, permission, sid, granting, success, failure}
}

func (ace *accessControlEntry) GetAcl() Acl {
	return ace.acl
}

func (ace *accessControlEntry) GetID() interface{} {
	return ace.id
}

func (ace *accessControlEntry) GetPermission() permission.Permission {
	return ace.permission
}

func (ace *accessControlEntry) GetSid() sid.Sid {
	return ace.sid
}

func (ace *accessControlEntry) IsGranting() bool {
	return ace.granting
}
func (ace *accessControlEntry) IsAuditFailure() bool {
	return ace.failure
}

func (ace *accessControlEntry) IsAuditSuccess() bool {
	return ace.succes
}

func (ace *accessControlEntry) setAuditFailure(failure bool) {
	ace.failure = failure
}

func (ace *accessControlEntry) setAuditSuccess(success bool) {
	ace.succes = success
}

func (ace *accessControlEntry) setPermission(permission permission.Permission) {
	ace.permission = permission
}

func (ace *accessControlEntry) String() string {
	return fmt.Sprintf(
		"AccessControlEntry[id: %s; granting: %t; sid: %s; permission: %s, auditSuccess: %t, auditFailure: %t]",
		ace.id,
		ace.granting,
		ace.sid,
		ace.permission,
		ace.succes,
		ace.failure,
	)
}
