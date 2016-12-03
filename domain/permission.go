package domain

import "github.com/streamtune/acl"

// DefaultPermissionGrantingStrategy is the default permission granting strategy implmentation.
type DefaultPermissionGrantingStrategy struct {
	logger AuditLogger
}

// NewDefaultPermissionGrantingStrategy is the factory method used to create a new default PermissionGrantingStrategy
func NewDefaultPermissionGrantingStrategy(logger AuditLogger) *DefaultPermissionGrantingStrategy {
	return &DefaultPermissionGrantingStrategy{logger}
}

// IsGranted will check the permission
func (s *DefaultPermissionGrantingStrategy) IsGranted(instance acl.Instance, perms []acl.Permission, sids []acl.Sid, admin bool) (bool, error) {
	aces := instance.GetEntries()
	var firstRejection acl.Ace
	for _, p := range perms {
		for _, sid := range sids {
			// Attempt to find the exact match for this permission mask and SID
			scanNextSid := false
			for _, ace := range aces {
				if ace.GetPermission().HasFlag(uint32(p)) && ace.GetSid().Equals(sid) {
					// Found a matching ACE, so its authorization decision will prevail
					if ace.IsGranting() {
						// Success
						if !admin {
							s.logger.LogIfNeeded(true, ace)
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
			s.logger.LogIfNeeded(false, firstRejection)
		}
	}

	// No matches have been found so far
	if parent := instance.GetParent(); parent != nil && instance.IsEntriesInheriting() {
		return parent.IsGranted(perms, sids, false)
	}
	// We either have no parent or we're the uppermost parent
	return false, acl.ErrNotFound
}
