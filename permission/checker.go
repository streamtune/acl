package permission

import (
	"errors"

	"github.com/streamtune/acl/sid"
)

// Auditable is exposed by auditable objects
type Auditable interface {
	IsAuditSuccess() bool
	IsAuditFailure() bool
}

// Auditor is exposed by auditor objects
type Auditor interface {
	Audit(bool, Auditable)
}

// Acl is the interface that ACL must complains to in order to be processed by permission checker
type Acl interface {
	GetEntries() []Ace
	GetParent() Acl
	IsEntriesInheriting() bool
}

// Ace is the interface that Access Control Entries must complains to in order to be processed by permission checker
type Ace interface {
	GetSid() sid.Sid
	GetPermission() Permission
	IsGranting() bool
}

// Checker is the default permission checker
type Checker struct {
	auditor Auditor
}

// NewChecker will create a new default permission checker
func NewChecker(auditor Auditor) *Checker {
	return &Checker{auditor: auditor}
}

// Check will perform the check the provided acl for given permissions and Sid
func (c *Checker) Check(acl Acl, permissions []Permission, sids []sid.Sid, admin bool) (bool, error) {
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
						if auditable, ok := ace.(Auditable); ok && !admin {
							c.auditor.Audit(true, auditable)
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
		if auditable, ok := firstRejection.(Auditable); ok && !admin {
			c.auditor.Audit(false, auditable)
		}
	}

	// No matches have been found so far
	if parent := acl.GetParent(); parent != nil && acl.IsEntriesInheriting() {
		return c.Check(parent, permissions, sids, admin)
	}
	// We either have no parent or we're the uppermost parent
	return false, errors.New("No entry found")
}
