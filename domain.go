package acl

import (
	"errors"
	"fmt"

	"reflect"
)

// DefaultLogger is the default logger implementation
func DefaultLogger(granted bool, ace Ace) {
	if auditable, ok := ace.(AuditableAce); ok {
		if granted && auditable.IsAuditSuccess() {
			fmt.Printf("Granted due to ACE %s", ace)
		} else if !granted && auditable.IsAuditFailure() {
			fmt.Printf("Denied due to ACE %s", ace)
		}
	}
}

// DefaultPermissionGranter is the default permission granter
func DefaultPermissionGranter(acl Acl, permissions []Permission, sids []Sid, admin bool, logger AuditLogger) (bool, error) {
	if logger == nil {
		logger = DefaultLogger
	}
	aces := acl.GetEntries()
	var firstRejection Ace
	for _, p := range permissions {
		for _, sid := range sids {
			// Attempt to find the exact match for this permission mask and SID
			scanNextSid := false
			for _, ace := range aces {
				if ace.GetPermission().Match(p) && ace.GetSid().Equals(sid) {
					// Found a matching ACE, so its authorization decision will prevail
					if ace.IsGranting() {
						// Success
						if !admin {
							logger(true, ace)
						}
						return true, nil
					}
					// Failure for this permission, so stop search. We will see if they have a different permission
					// (this permission is 100% rejected for this SID)
					if firstRejection == nil {
						// Store first rejection for auditing purposes
						firstRejection = ace
					}
					scanNextSid = false // Helps break the loop
					break
				}
			}
			if !scanNextSid {
				break
			}
		}
	}
	if firstRejection != nil {
		// We found an ACE to reject the request at this point, as no other ACEs where found that granted a different
		// permission
		if !admin {
			logger(false, firstRejection)
		}
	}

	// No matches have been found so far
	if parent := acl.GetParent(); parent != nil && acl.IsEntriesInheriting() {
		return acl.IsGranted(permissions, sids, false)
	}
	// We either have no parent or we're the uppermost parent
	return false, ErrNotFound
}

// AuthoritySid is a Sid implementation holding a granted authority
type AuthoritySid string

// Equals will check if the receiver is equal to provided Sid implementation
func (s AuthoritySid) Equals(other Sid) bool {
	if o, ok := other.(AuthoritySid); ok {
		return s == o
	}
	return false
}

// GetAuthority retrieve the authority for the receiver authority Sid.
func (s AuthoritySid) GetAuthority() string {
	return string(s)
}

// PrincipalSid is a Sid implementation holding a principal
type PrincipalSid string

// Equals will check if the receiver is equal to provided Sid implementation
func (p PrincipalSid) Equals(other Sid) bool {
	if o, ok := other.(PrincipalSid); ok {
		return p == o
	}
	return false
}

// GetPrincipal retrieve the principal for the receiver principal Sid.
func (p PrincipalSid) GetPrincipal() string {
	return string(p)
}

// DefaultSidRetriever is the default function used to retrieve the list of Sid
func DefaultSidRetriever(auth Authentication) []Sid {
	roles := auth.GetAuthorities()
	sids := make([]Sid, len(roles)+1)
	sids = append(sids, PrincipalSid(auth.GetPrincipal()))
	for _, role := range roles {
		sids = append(sids, AuthoritySid(role))
	}
	return sids
}

// ObjectIdentity is the concrete type for Oid interface
type ObjectIdentity struct {
	kind string
	id   interface{}
}

// NewObjectIdentity will create new identity instance
func NewObjectIdentity(kind string, id interface{}) *ObjectIdentity {
	return &ObjectIdentity{kind, id}
}

// GetIdentifier retrieve the identifier of the identity
func (oid *ObjectIdentity) GetIdentifier() interface{} {
	return oid.id
}

// GetType retrieve the type of the identity
func (oid *ObjectIdentity) GetType() string {
	return oid.kind
}

// Equals will check if this identity is equal to other one
func (oid *ObjectIdentity) Equals(other Oid) bool {
	if o, ok := other.(*ObjectIdentity); ok {
		return oid.id == o.id && oid.kind == o.kind
	}
	return false
}

func (oid *ObjectIdentity) String() string {
	return fmt.Sprintf("ObjectIdentity[kind: %s, id: %s]", oid.kind, oid.id)
}

// DefaultOidGenerator is the default object identity generator
func DefaultOidGenerator(id interface{}, kind string) (Oid, error) {
	return NewObjectIdentity(kind, id), nil
}

type idGetter interface {
	GetID() interface{}
}

// DefaultOidRetriever is the default object identity retriever
func DefaultOidRetriever(object interface{}) (Oid, error) {
	kind := reflect.TypeOf(object).Name()
	if getter, ok := object.(idGetter); ok {
		id := getter.GetID()
		return NewObjectIdentity(kind, id), nil
	}
	return nil, fmt.Errorf("Object %x does not provide a GetID method", object)
}

// ChangeType is the type of change that can be applied to an Acl.
type ChangeType int

// ChangeOwnership is a change in ownership of Acl
// ChangeAuditing is a change of auditing behavior
// ChangeGeneral is any other type of change
const (
	ChangeOwnership ChangeType = iota
	ChangeAuditing
	ChangeGeneral
)

// Authorizer is used by Acl to determine whether a principal is permitted to call adminstrative methods
// on the implementation itself
type Authorizer interface {
	SecurityCheck(Authentication, Acl, ChangeType) error
}

// DefaultAuthorizer is the default implementation of Authorizer.
//
// Permission will be granted if at least one of the following conditions is true for the current principal.
// - Is the owner (as defined by ACL)
// - Holds relevant granted authorities.
// - Has BasePermission Adminnistration permission (as defined by the ACL).
type DefaultAuthorizer struct {
	generalChange   string
	auditingChange  string
	ownershipChange string
	getSids         SidRetriever
}

// NewDefaultAuthorizer will create a new default AuthorizationStrategy
func NewDefaultAuthorizer(general, auditing, ownership string) *DefaultAuthorizer {
	return &DefaultAuthorizer{general, auditing, ownership, DefaultSidRetriever}
}

// SecurityCheck perform the security check for the given change type
func (s *DefaultAuthorizer) SecurityCheck(auth Authentication, acl Acl, change ChangeType) error {
	if auth == nil {
		return errors.New("Authenticated principal required to operate with ACLs")
	}
	currentUser := PrincipalSid(auth.GetPrincipal())
	if currentUser.Equals(acl.GetOwner()) && (change == ChangeGeneral || change == ChangeOwnership) {
		return nil
	}
	// Not authorized by ACL ownership; try via administrtive permissions
	var requiredAuthority string
	switch change {
	case ChangeAuditing:
		requiredAuthority = s.auditingChange
	case ChangeGeneral:
		requiredAuthority = s.generalChange
	case ChangeOwnership:
		requiredAuthority = s.ownershipChange
	default:
		return errors.New("Unsupported change type")
	}
	// Iterate the principal's authorities to determine right
	for _, v := range auth.GetAuthorities() {
		if v == requiredAuthority {
			return nil
		}
	}
	// Try to get permissions via ACEs within the ACL
	sids := s.getSids(auth)
	permissions := []Permission{AdministrationPermission}
	if ok, err := acl.IsGranted(permissions, sids, false); err != nil && ok {
		return nil
	}

	return errors.New("Principal does not have required ACL permissions to perform required operation.")
}

// AccessControlEntry is the basic implementation of an Ace interface
type accessControlEntry struct {
	id         interface{}
	acl        Acl
	permission Permission
	sid        Sid
	granting   bool
	succes     bool
	failure    bool
}

// NewAccessControlEntry will create a new Ace instance
func newAccessControlEntry(id interface{}, acl Acl, sid Sid, permission Permission, granting, success, failure bool) (*accessControlEntry, error) {
	if acl == nil {
		return nil, errors.New("Acl object is required")
	}
	if sid == nil {
		return nil, errors.New("Sid object is required")
	}
	return &accessControlEntry{id, acl, permission, sid, granting, success, failure}, nil
}

// GetAcl will retrieve the Acl
func (ace *accessControlEntry) GetAcl() Acl {
	return ace.acl
}

// GetID will retrieve the id
func (ace *accessControlEntry) GetID() interface{} {
	return ace.id
}

// GetPermission will retrieve the permission
func (ace *accessControlEntry) GetPermission() Permission {
	return ace.permission
}

// GetSid will retrieve the Sid
func (ace *accessControlEntry) GetSid() Sid {
	return ace.sid
}

// IsAuditFailure check if this ACE should log failures
func (ace *accessControlEntry) IsAuditFailure() bool {
	return ace.failure
}

// IsAuditSuccess check if this ACE should log successes
func (ace *accessControlEntry) IsAuditSuccess() bool {
	return ace.succes
}

// IsGranting check if this ACE permission are granted
func (ace *accessControlEntry) IsGranting() bool {
	return ace.granting
}

// SetAuditFailure will change the audit failure behavior
func (ace *accessControlEntry) SetAuditFailure(failure bool) {
	ace.failure = failure
}

// SetAuditSuccess will change the audit success behavior
func (ace *accessControlEntry) SetAuditSuccess(success bool) {
	ace.succes = success
}

// SetPermission will change the permission of this ACE
func (ace *accessControlEntry) SetPermission(permission Permission) {
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

// acl is the implementation class of Acl interface
type acl struct {
	id         interface{}
	oid        Oid
	owner      Sid
	parent     Acl
	authorizer Authorizer
	granter    PermissionGranter
	aces       []Ace
	inherits   bool
	loadedSids []Sid
	logger     AuditLogger
}

// newAcl will create a new ACL instance with full parameters.
func newAcl(oid Oid, id interface{}, auth Authorizer, granter PermissionGranter, log AuditLogger, parent Acl, loadedSids []Sid, inherits bool, owner Sid) (*acl, error) {
	if auth == nil {
		return nil, errors.New("Authorizer must not be null")
	}
	if granter == nil {
		return nil, errors.New("Granter must not be null")
	}
	if log == nil {
		log = DefaultLogger
	}
	return &acl{
		id:         id,
		oid:        oid,
		owner:      owner,
		parent:     parent,
		authorizer: auth,
		granter:    granter,
		inherits:   inherits,
		loadedSids: loadedSids,
		logger:     log,
	}, nil
}

func (a *acl) verifyIndexExists(index int) error {
	if index < 0 {
		return errors.New("index must be greater thant or equal to zero")
	}
	if index >= len(a.aces) {
		return fmt.Errorf("index must refer to an index of Ace list. List size is %d, index was %d", len(a.aces), index)
	}
	return nil
}

// InsertAce will create and insert a new Ace.
func (a *acl) InsertAce(index int, permission Permission, sid Sid, granting bool) error {
	// TODO retrieve Authentication object
	var auth Authentication
	a.authorizer.SecurityCheck(auth, a, ChangeGeneral)
	if index < 0 || index > len(a.aces) {
		return ErrNotFound
	}
	ace, err := newAccessControlEntry(nil, a, sid, permission, granting, false, false)
	if err != nil {
		return err
	}
	a.aces = append(a.aces[:index], append([]Ace{ace}, a.aces[index:]...)...)
	return nil
}

// DeleteAce will delete the Ace at provided index
func (a *acl) DeleteAce(index int) error {
	if err := a.verifyIndexExists(index); err != nil {
		return err
	}
	a.aces = append(a.aces[:index], a.aces[index+1:]...)
	return nil
}

// GetEntries will retrieve all the entries
func (a *acl) GetEntries() []Ace {
	result := make([]Ace, len(a.aces))
	copy(result, a.aces)
	return result
}

// GetID will retrieve the unique object id
func (a *acl) GetID() interface{} {
	return a.id
}

// GetIdentity will retrieve the object identity
func (a *acl) GetIdentity() Oid {
	return a.oid
}

// IsEntriesInheriting will check if this acl object inherits
func (a *acl) IsEntriesInheriting() bool {
	return a.inherits
}

// IsGranted delegates to Granter
func (a *acl) IsGranted(permissions []Permission, sids []Sid, admin bool) (bool, error) {
	if !a.IsSidLoaded(sids) {
		return false, ErrSidUnloaded
	}
	return a.granter(a, permissions, sids, admin, a.logger)
}

func (a *acl) IsSidLoaded(sids []Sid) bool {
	// If loadedSids is nul, this indicates all SIDs were loaded. Also return true if the callre didn't specify a SID
	if a.loadedSids == nil || sids == nil || len(sids) == 0 {
		return true
	}
	// This ACL applies to a SID subset only. Iterate to check if applies.
	for _, sid := range sids {
		found := false
		for _, loadedSid := range a.loadedSids {
			if sid.Equals(loadedSid) {
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

func (a *acl) SetEntriesInheriting(entriesInheriting bool) error {
	var auth Authentication
	if err := a.authorizer.SecurityCheck(auth, a, ChangeGeneral); err != nil {
		return err
	}
	a.inherits = entriesInheriting
	return nil
}

func (a *acl) SetOwner(newOwner Sid) error {
	var auth Authentication
	if err := a.authorizer.SecurityCheck(auth, a, ChangeOwnership); err != nil {
		return err
	}
	a.owner = newOwner
	return nil
}

func (a *acl) GetOwner() Sid {
	return a.owner
}

func (a *acl) SetParent(newParent Acl) error {
	var auth Authentication
	if err := a.authorizer.SecurityCheck(auth, a, ChangeGeneral); err != nil {
		return err
	}
	if newParent != nil && a == newParent {
		return errors.New("Cannot be the parent of yourself")
	}
	a.parent = newParent
	return nil
}

func (a *acl) GetParent() Acl {
	return a.parent
}

func (a *acl) UpdateAce(index int, permission Permission) error {
	var auth Authentication
	if err := a.authorizer.SecurityCheck(auth, a, ChangeGeneral); err != nil {
		return err
	}
	if err := a.verifyIndexExists(index); err != nil {
		return err
	}
	if ace, ok := a.aces[index].(*accessControlEntry); ok {
		ace.SetPermission(permission)
		return nil
	}
	return errors.New("Ace is not of accessControlEntry type")
}

func (a *acl) UpdateAuditing(index int, succes, failure bool) error {
	var auth Authentication
	if err := a.authorizer.SecurityCheck(auth, a, ChangeAuditing); err != nil {
		return err
	}
	if err := a.verifyIndexExists(index); err != nil {
		return err
	}
	if ace, ok := a.aces[index].(*accessControlEntry); ok {
		ace.SetAuditSuccess(succes)
		ace.SetAuditFailure(failure)
	}
	return errors.New("Ace is not of AccessControlEntryImpl type")
}
