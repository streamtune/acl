package acl

import (
	"errors"

	"github.com/streamtune/acl/audit"
	"github.com/streamtune/acl/permission"
	"github.com/streamtune/acl/sid"
)

// Checker is the interface used to check permissions
type Checker interface {
	Check(Acl, []permission.Permission, []sid.Sid, bool) (bool, error)
}

type checker struct {
	auditor audit.Auditor
}

// Check will perform the check the provided acl for given permissions and Sid
func (c *checker) Check(acl Acl, permissions []permission.Permission, sids []sid.Sid, admin bool) (bool, error) {
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
						if auditable, ok := ace.(audit.Auditable); ok && !admin {
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
		if auditable, ok := firstRejection.(audit.Auditable); ok && !admin {
			c.auditor.Audit(false, auditable)
		}
	}

	// No matches have been found so far
	if parent := acl.GetParent(); parent != nil && acl.IsEntriesInheriting() {
		return parent.IsGranted(permissions, sids, admin)
	}
	// We either have no parent or we're the uppermost parent
	return false, errors.New("No entry found")
}

// NewChecker will create a new default permission checker
func NewChecker(auditor audit.Auditor) Checker {
	return &checker{auditor: auditor}
}

// DefaultChecker will return the default checker initialized with default Auditor
func DefaultChecker() Checker {
	return NewChecker(audit.Default())
}
