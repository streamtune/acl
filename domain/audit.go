package domain

import "github.com/streamtune/acl"
import "fmt"

// AuditLogger is used in order to audit logging data.
type AuditLogger interface {
	LogIfNeeded(granted bool, ace acl.Ace)
}

// ConsoleAuditLogger is an AuditLogger used to log audit information on console
type ConsoleAuditLogger struct {
}

// NewConsoleAuditLogger is the factory function used to create new ConsoleAuditLogger
func NewConsoleAuditLogger() *ConsoleAuditLogger {
	return &ConsoleAuditLogger{}
}

// LogIfNeeded is the method invoked when someone wants to log a grant or a deny action.
func (c *ConsoleAuditLogger) LogIfNeeded(granted bool, ace acl.Ace) {
	if auditable, ok := ace.(acl.AuditableAce); ok {
		if granted && auditable.IsAuditSuccess() {
			fmt.Printf("Granted due to ACE %s", ace)
		} else if !granted && auditable.IsAuditFailure() {
			fmt.Printf("Denied due to ACE %s", ace)
		}
	}
}
