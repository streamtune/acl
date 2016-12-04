package security

import (
	"context"
	"errors"

	"github.com/streamtune/acl/permission"
	"github.com/streamtune/acl/sid"
)

// Acl is the interface to which all the object must complains to
type Acl interface {
	GetOwner() sid.Sid
	IsGranted([]permission.Permission, []sid.Sid, bool) (bool, error)
}

// Authorizer is the default implementation of Authorizer.
//
// Permission will be granted if at least one of the following conditions is true for the current principal.
// - Is the owner (as defined by ACL)
// - Holds relevant granted authorities.
// - Has BasePermission Adminnistration permission (as defined by the ACL).
type Authorizer struct {
	generalChange   *sid.Authority
	auditingChange  *sid.Authority
	ownershipChange *sid.Authority
}

// NewAuthorizer will create a new default AuthorizationStrategy
func NewAuthorizer(general, auditing, ownership string) *Authorizer {
	return &Authorizer{sid.NewAuthority(general), sid.NewAuthority(auditing), sid.NewAuthority(ownership)}
}

// Authorize perform the security check for the given change type
func (a *Authorizer) Authorize(ctx context.Context, acl Acl, change ChangeType) error {
	if ctx == nil {
		return errors.New("Context is required to operate on acl.")
	}
	sids, err := sid.NewFromContext(ctx)
	if err != nil {
		return err
	}
	currentUser := sids[0]
	if currentUser.Equals(acl.GetOwner()) && (change == ChangeGeneral || change == ChangeOwnership) {
		return nil
	}
	// Not authorized by ACL ownership; try via administrtive permissions
	var requiredAuthority interface{}
	switch change {
	case ChangeAuditing:
		requiredAuthority = a.auditingChange
	case ChangeGeneral:
		requiredAuthority = a.generalChange
	case ChangeOwnership:
		requiredAuthority = a.ownershipChange
	default:
		return errors.New("Unsupported change type")
	}
	// Iterate the principal's authorities to determine right
	for _, v := range sids {
		if v.Equals(requiredAuthority) {
			return nil
		}
	}
	// Try to get permissions via ACEs within the ACL
	permissions := []permission.Permission{permission.Administration}
	if ok, err := acl.IsGranted(permissions, sids, false); err != nil && ok {
		return nil
	}

	return errors.New("Principal does not have required ACL permissions to perform required operation.")
}
