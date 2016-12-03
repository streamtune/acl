package domain

import (
	"errors"
	"fmt"

	"github.com/streamtune/acl"
)

// AccessControlEntry is the basic implementation of an Ace interface
type AccessControlEntry struct {
	acl      acl.Instance
	perm     acl.Permission
	id       interface{}
	sid      acl.Sid
	granting bool
	succes   bool
	failure  bool
}

// NewAccessControlEntry will create a new Ace instance
func NewAccessControlEntry(id interface{}, acl acl.Instance, sid acl.Sid, perm acl.Permission, granting, success, failure bool) (*AccessControlEntry, error) {
	if acl == nil {
		return nil, errors.New("Acl object is required")
	}
	if sid == nil {
		return nil, errors.New("Sid object is required")
	}
	if perm == nil {
		return nil, errors.New("Permission object is required")
	}
	return &AccessControlEntry{acl, perm, id, sid, granting, success, failure}, nil
}

// GetAcl will retrieve the Acl
func (ace *AccessControlEntry) GetAcl() acl.Instance {
	return ace.acl
}

// GetID will retrieve the id
func (ace *AccessControlEntry) GetID() interface{} {
	return ace.id
}

// GetPermission will retrieve the permission
func (ace *AccessControlEntry) GetPermission() acl.Permission {
	return ace.perm
}

// GetSid will retrieve the Sid
func (ace *AccessControlEntry) GetSid() acl.Sid {
	return ace.sid
}

// IsAuditFailure check if this ACE should log failures
func (ace *AccessControlEntry) IsAuditFailure() bool {
	return ace.failure
}

// IsAuditSuccess check if this ACE should log successes
func (ace *AccessControlEntry) IsAuditSuccess() bool {
	return ace.succes
}

// IsGranting check if this ACE permission are granted
func (ace *AccessControlEntry) IsGranting() bool {
	return ace.granting
}

// SetAuditFailure will change the audit failure behavior
func (ace *AccessControlEntry) SetAuditFailure(failure bool) {
	ace.failure = failure
}

// SetAuditSuccess will change the audit success behavior
func (ace *AccessControlEntry) SetAuditSuccess(success bool) {
	ace.succes = success
}

// SetPermission will change the permission of this ACE
func (ace *AccessControlEntry) SetPermission(perm acl.Permission) {
	ace.perm = perm
}

func (ace *AccessControlEntry) String() string {
	return fmt.Sprintf(
		"AccessControlEntry[id: %s; granting: %t; sid: %s; permission: %s, auditSuccess: %t, auditFailure: %t]",
		ace.id,
		ace.granting,
		ace.sid,
		ace.perm,
		ace.succes,
		ace.failure,
	)
}
