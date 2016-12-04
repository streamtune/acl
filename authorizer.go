package acl

import (
	"context"
	"errors"

	"github.com/streamtune/acl/change"
	"github.com/streamtune/acl/permission"
	"github.com/streamtune/acl/sid"
)

// Authorizer is the interface exposed by object that authorize changes on Acl
type Authorizer interface {
	Authorize(context.Context, Acl, change.Type) error
}

// authorizer is the default implementation of Authorizer.
//
// Permission will be granted if at least one of the following conditions is true for the current principal.
// - Is the owner (as defined by ACL)
// - Holds relevant granted authorities.
// - Has BasePermission Adminnistration permission (as defined by the ACL).
type authorizer struct {
	authorizations map[change.Type]sid.Sid
}

// Authorize perform the security check for the given change type
func (a *authorizer) Authorize(ctx context.Context, acl Acl, chg change.Type) error {
	if ctx == nil {
		return errors.New("Context is required to operate on acl.")
	}
	sids, err := sid.Retrieve(ctx)
	if err != nil {
		return err
	}
	currentUser := sids[0]
	if currentUser.Equals(acl.GetOwner()) && (chg == change.General || chg == change.Ownership) {
		return nil
	}
	// Not authorized by ACL ownership; try via administrtive permissions
	authority, ok := a.authorizations[chg]
	if !ok {
		return errors.New("Unsupported change type")
	}
	// Iterate the principal's authorities to determine right
	for _, v := range sids {
		if v.Equals(authority) {
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

// NewAuthorizer will create a new default AuthorizationStrategy
func NewAuthorizer(general, auditing, ownership string) (Authorizer, error) {
	authorizer := new(authorizer)
	authorizer.authorizations = make(map[change.Type]sid.Sid)
	s, err := sid.ForAuthority(general)
	if err != nil {
		return nil, err
	}
	authorizer.authorizations[change.General] = s
	s, err = sid.ForAuthority(auditing)
	if err != nil {
		return nil, err
	}
	authorizer.authorizations[change.Auditing] = s
	s, err = sid.ForAuthority(ownership)
	if err != nil {
		return nil, err
	}
	return authorizer, nil
}

// SimpleAuthorizer return a new authorizer with the single provieded authority for all three change types
func SimpleAuthorizer(authority string) (Authorizer, error) {
	return NewAuthorizer(authority, authority, authority)
}
