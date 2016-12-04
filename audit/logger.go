package audit

import "fmt"

// Auditable is the interface exposed by Ace that can be audited.
type Auditable interface {
	// Check if entry must audit success
	IsAuditSuccess() bool
	// Check if entry must audit failures
	IsAuditFailure() bool
}

// Auditor is the basic interface for auditing.
type Auditor interface {
	Audit(bool, Auditable)
}

// Console is an object instance used to log auditing information on console
type consoleAuditor struct{}

// Audit will perform auditing over console
func (c *consoleAuditor) Audit(granted bool, ace Auditable) {
	if granted && ace.IsAuditSuccess() {
		fmt.Printf("Granted due to ACE %s", ace)
	} else if !granted && ace.IsAuditFailure() {
		fmt.Printf("Denied due to ACE %s", ace)
	}
}

// Console will return the console auditor
func Console() Auditor {
	return new(consoleAuditor)
}

// Default will return the default auditor
func Default() Auditor {
	return Console()
}
