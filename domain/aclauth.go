package domain

import (
	"errors"

	"github.com/streamtune/acl"
)

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
	SecurityCheck(acl.Authentication, acl.Instance, ChangeType) error
}

// DefaultAuthorizationStrategy is the default implementation of AuthorizationStrategy.
//
// Permission will be granted if at least one of the following conditions is true for the current principal.
// - Is the owner (as defined by ACL)
// - Holds relevant granted authorities.
// - Has BasePermission Adminnistration permission (as defined by the ACL).
type DefaultAuthorizationStrategy struct {
	generalChange   string
	auditingChange  string
	ownershipChange string
	sidrs           acl.SidRetrievalStrategy
}

// NewDefaultAuthorizationStrategy will create a new default AuthorizationStrategy
func NewDefaultAuthorizationStrategy(general, auditing, ownership string) *DefaultAuthorizationStrategy {
	return &DefaultAuthorizationStrategy{general, auditing, ownership, NewDefaultSidRetrievalStrategy()}
}

// SecurityCheck perform the security check for the given change type
func (s *DefaultAuthorizationStrategy) SecurityCheck(auth acl.Authentication, instance acl.Instance, change ChangeType) error {
	if auth == nil {
		return errors.New("Authenticated principal required to operate with ACLs")
	}
	currentUser := NewPrincipalSid(auth.GetPrincipal())
	if currentUser.Equals(instance.GetOwner()) && (change == ChangeGeneral || change == ChangeOwnership) {
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
	sids := s.sidrs.GetSids(auth)
	perms := []acl.Permission{AdministrationPermission}
	if ok, err := instance.IsGranted(perms, sids, false); err != nil && ok {
		return nil
	}

	return errors.New("Principal does not have required ACL permissions to perform required operation.")
}
