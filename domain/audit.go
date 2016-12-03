package domain

import "github.com/streamtune/acl"

// AuditLogger is used in order to audit logging data.
type AuditLogger interface {
	LogIfNeeded(granted bool, ace acl.Ace)
}
