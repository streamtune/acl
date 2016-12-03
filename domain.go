package acl

import (
	"errors"
	"fmt"
)

// ReadPermission is used in order to read a value
// WritePermission is used in order to write a value
// CreatePermisssion is used in order to create a new value
// DeletePermission is used in order to delete a value
// AdministrationPermission is used in order to allow administration tasks
const (
	ReadPermission Permission = 1 << iota
	WritePermission
	CreatePermisssion
	DeletePermission
	AdministrationPermission
)

// Ace is the basic implementation of an AccessControlEntry interface
type Ace struct {
	acl      Acl
	perm     Permission
	id       interface{}
	sid      Sid
	granting bool
	succes   bool
	failure  bool
}

// newAce will create a new defaultAce instance
func newAce(id interface{}, acl Acl, sid Sid, perm Permission, granting, success, failure bool) (*Ace, error) {
	if acl == nil {
		return nil, errors.New("Acl object is required")
	}
	if sid == nil {
		return nil, errors.New("Sid object is required")
	}
	if perm == nil {
		return nil, errors.New("Permission object is required")
	}
	return &Ace{acl, perm, id, sid, granting, success, failure}, nil
}

// GetAcl will retrieve the Acl
func (ace *Ace) GetAcl() Acl {
	return ace.acl
}

// GetID will retrieve the id
func (ace *Ace) GetID() interface{} {
	return ace.id
}

// GetPermission will retrieve the permission
func (ace *Ace) GetPermission() Permission {
	return ace.perm
}

// GetSid will retrieve the Sid
func (ace *Ace) GetSid() Sid {
	return ace.sid
}

// IsAuditFailure check if this ACE should log failures
func (ace *Ace) IsAuditFailure() bool {
	return ace.failure
}

// IsAuditSuccess check if this ACE should log successes
func (ace *Ace) IsAuditSuccess() bool {
	return ace.succes
}

// IsGranting check if this ACE permission are granted
func (ace *Ace) IsGranting() bool {
	return ace.granting
}

// SetAuditFailure will change the audit failure behavior
func (ace *Ace) SetAuditFailure(failure bool) {
	ace.failure = failure
}

// SetAuditSuccess will change the audit success behavior
func (ace *Ace) SetAuditSuccess(success bool) {
	ace.succes = success
}

// SetPermission will change the permission of this ACE
func (ace *Ace) SetPermission(perm Permission) error {
	if perm == nil {
		return errors.New("Permission required")
	}
	ace.perm = perm
	return nil
}

func (ace *Ace) String() string {
	return fmt.Sprintf(
		"Ace[id: %s; granting: %t; sid: %s; permission: %s, auditSuccess: %t, auditFailure: %t]",
		ace.id,
		ace.granting,
		ace.sid,
		ace.perm,
		ace.succes,
		ace.failure,
	)
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

// AuthorizationStrategy is used by Impl to determine whether a principal is permitted to call adminstrative methods
// on the implementation itself
type AuthorizationStrategy interface {
	// Perform the security check on provided change type, returning an error if the check fails.
	SecurityCheck(Authentication, Acl, ChangeType) error
}

// DefaultAuthorizationStrategy is the default implementation of AuthorizationStrategy.
//
// Permission will be granted if at least one of the following conditions is true for the current principal.
// - Is the owner (as defined by ACL)
// - Holds relevant granted authorities.
// - Has BasePermission Adminnistration permission (as defined by the ACL).
type DefaultAuthorizationStrategy struct {
	generalChange        string
	auditingChange       string
	ownershipChange      string
	sidRetrievalStrategy SidRetrievalStrategy
}

// NewDefaultAuthorizationStrategy will create a new default AuthorizationStrategy
func NewDefaultAuthorizationStrategy(general, auditing, ownership string) *DefaultAuthorizationStrategy {
	return &DefaultAuthorizationStrategy{general, auditing, ownership, NewDefaultSidRetrievalStrategy()}
}

// SecurityCheck perform the security check for the given change type
func (s *DefaultAuthorizationStrategy) SecurityCheck(auth Authentication, acl Acl, change ChangeType) error {
	if auth == nil {
		return errors.New("Authenticated principal required to operate with ACLs")
	}
	currentUser := NewPrincipalSid(auth.GetPrincipal())
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
	sids := s.sidRetrievalStrategy.GetSids(auth)
	perms := []Permission{AdministrationPermission}
	if ok, err := acl.IsGranted(perms, sids, false); err != nil && ok {
		return nil
	}

	return errors.New("Principal does not have required ACL permissions to perform required operation.")
}

// AuditLogger is used in order to audit logging data.
type AuditLogger interface {
	LogIfNeeded(granted bool, ace AccessControlEntry)
}

// AuthoritySid is a Sid implementation holding a role
type AuthoritySid struct {
	authority string
}

// NewAuthoritySid will create a new AuthoritySid object instance
func NewAuthoritySid(authority string) *AuthoritySid {
	return &AuthoritySid{authority}
}

// Equals will check if the receiver is equal to provided Sid implementation
func (s *AuthoritySid) Equals(other Sid) bool {
	if o, ok := other.(*AuthoritySid); ok {
		return s.authority == o.authority
	}
	return false
}

// GetAuthority retrieve the authority for the receiver authority Sid.
func (s *AuthoritySid) GetAuthority() string {
	return s.authority
}

func (s *AuthoritySid) String() string {
	return fmt.Sprintf("AuthoritySid[%s]", s.authority)
}

// PrincipalSid is a Sid implementation holding a principal
type PrincipalSid struct {
	principal string
}

// NewPrincipalSid will create a new PrincipalSid object instance
func NewPrincipalSid(principal string) *PrincipalSid {
	return &PrincipalSid{principal}
}

// Equals will check if the receiver is equal to provided Sid implementation
func (p *PrincipalSid) Equals(other Sid) bool {
	if o, ok := other.(*PrincipalSid); ok {
		return p.principal == o.principal
	}
	return false
}

// GetPrincipal retrieve the principal for the receiver principal Sid.
func (p *PrincipalSid) GetPrincipal() string {
	return p.principal
}

func (p *PrincipalSid) String() string {
	return fmt.Sprintf("PrincipalSid[%s]", p.principal)
}

// DefaultSidRetrievalStrategy is a basic implementation of SidRetrievalStrategy that creates a Sid for the principal, as
// well as every granted authority the principal holds.
type DefaultSidRetrievalStrategy struct {
	// TODO optionally provide a role hierarchy
}

// NewDefaultSidRetrievalStrategy will create a new SidRetrievalStrategyImpl instance
func NewDefaultSidRetrievalStrategy() *DefaultSidRetrievalStrategy {
	return &DefaultSidRetrievalStrategy{}
}

// GetSids will retrieve the sids for given authentication object
func (s *DefaultSidRetrievalStrategy) GetSids(auth Authentication) []Sid {
	roles := auth.GetAuthorities()
	sids := make([]Sid, len(roles)+1)
	sids = append(sids, NewPrincipalSid(auth.GetPrincipal()))
	for _, role := range roles {
		sids = append(sids, NewAuthoritySid(role))
	}
	return sids
}
