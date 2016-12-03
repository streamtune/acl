package acl

import (
	"errors"
	"fmt"
)

// AccessControlEntryImpl is the basic implementation of an AccessControlEntry interface
type AccessControlEntryImpl struct {
	acl      Acl
	perm     Permission
	id       interface{}
	sid      Sid
	granting bool
	succes   bool
	failure  bool
}

// NewAccessControlEntryImpl will create a new AccessControlEntryImpl instance
func NewAccessControlEntryImpl(id interface{}, acl Acl, sid Sid, perm Permission, granting, success, failure bool) (*AccessControlEntryImpl, error) {
	if acl == nil {
		return nil, errors.New("Acl object is required")
	}
	if sid == nil {
		return nil, errors.New("Sid object is required")
	}
	if perm == nil {
		return nil, errors.New("Permission object is required")
	}
	return &AccessControlEntryImpl{acl, perm, id, sid, granting, success, failure}, nil
}

// GetAcl will retrieve the Acl
func (ace *AccessControlEntryImpl) GetAcl() Acl {
	return ace.acl
}

// GetID will retrieve the id
func (ace *AccessControlEntryImpl) GetID() interface{} {
	return ace.id
}

// GetPermission will retrieve the permission
func (ace *AccessControlEntryImpl) GetPermission() Permission {
	return ace.perm
}

// GetSid will retrieve the Sid
func (ace *AccessControlEntryImpl) GetSid() Sid {
	return ace.sid
}

// IsAuditFailure check if this ACE should log failures
func (ace *AccessControlEntryImpl) IsAuditFailure() bool {
	return ace.failure
}

// IsAuditSuccess check if this ACE should log successes
func (ace *AccessControlEntryImpl) IsAuditSuccess() bool {
	return ace.succes
}

// IsGranting check if this ACE permission are granted
func (ace *AccessControlEntryImpl) IsGranting() bool {
	return ace.granting
}

// SetAuditFailure will change the audit failure behavior
func (ace *AccessControlEntryImpl) SetAuditFailure(failure bool) {
	ace.failure = failure
}

// SetAuditSuccess will change the audit success behavior
func (ace *AccessControlEntryImpl) SetAuditSuccess(success bool) {
	ace.succes = success
}

// SetPermission will change the permission of this ACE
func (ace *AccessControlEntryImpl) SetPermission(perm Permission) error {
	if perm == nil {
		return errors.New("Permission required")
	}
	ace.perm = perm
	return nil
}

func (ace *AccessControlEntryImpl) String() string {
	return fmt.Sprintf(
		"AccessControlEntryImpl[id: %s; granting: %t; sid: %s; permission: %s, auditSuccess: %t, auditFailure: %t]",
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

// SidRetrievalStrategyImpl is a basic implementation of SidRetrievalStrategy that creates a Sid for the principal, as
// well as every granted authority the principal holds.
type SidRetrievalStrategyImpl struct {
	// TODO optionally provide a role hierarchy
}

// NewSidRetrievalStrategyImpl will create a new SidRetrievalStrategyImpl instance
func NewSidRetrievalStrategyImpl() *SidRetrievalStrategyImpl {
	return &SidRetrievalStrategyImpl{}
}

// GetSids will retrieve the sids for given authentication object
func (s *SidRetrievalStrategyImpl) GetSids(auth Authentication) []Sid {
	roles := auth.GetAuthorities()
	sids := make([]Sid, len(roles)+1)
	sids = append(sids, NewPrincipalSid(auth.GetPrincipal()))
	for _, role := range roles {
		sids = append(sids, NewAuthoritySid(role))
	}
	return sids
}

// BasePermission is the basic permission
type BasePermission struct {
	mask Bitmask
}

// NewBasePermission will create a new BasePermission object instance with given code and mask
func NewBasePermission(mask Bitmask) *BasePermission {
	return &BasePermission{mask}
}

// GetMask will retrieve the mask for the receiver permission
func (p *BasePermission) GetMask() Bitmask {
	return p.mask
}

// GetPattern will retrieve the pattern for the receiver permission
func (p *BasePermission) GetPattern() string {
	return p.mask.String()
}

// Equals will check if the receiver base permission is equal to provided other permission
func (p *BasePermission) Equals(other Permission) bool {
	if o, ok := other.(*BasePermission); ok {
		return p.mask == o.mask
	}
	return false
}

func (p *BasePermission) String() string {
	return fmt.Sprintf("BasePermission[%s=%d]", p.GetPattern(), p.mask)
}

// CumulativePermission represents a Permission that is constructed at runtime from other permissions.
type CumulativePermission struct {
	mask Bitmask
}

// NewCumulativePermission will create a new CumulativePermission
func NewCumulativePermission() *CumulativePermission {
	return &CumulativePermission{0}
}

// Clear will clear a single permission flag
func (c *CumulativePermission) Clear(perm Permission) {
	c.mask.removeFlag(perm.GetMask())
}

// ClearAll will clear all the permission flags
func (c *CumulativePermission) ClearAll() {
	c.mask.removeAll()
}

// Set will set the permission flag
func (c *CumulativePermission) Set(perm Permission) {
	c.mask.addFlag(perm.GetMask())
}

// GetMask will retrieve the permission mask
func (c *CumulativePermission) GetMask() Bitmask {
	return c.mask
}

// GetPattern will retrieve the permission pattern
func (c CumulativePermission) GetPattern() string {
	return c.mask.String()
}

// Equals will check if the receiver base permission is equal to provided other permission
func (c *CumulativePermission) Equals(other Permission) bool {
	if o, ok := other.(*CumulativePermission); ok {
		return c.mask == o.mask
	}
	return false
}

func (c CumulativePermission) String() string {
	return fmt.Sprintf("CumulativePermission[%s=%d]", c.mask, uint32(c.mask))
}
