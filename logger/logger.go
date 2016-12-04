package logger

import "fmt"

// Auditable is the interface that must be implemented by ACE object that must be logged
type Auditable interface {
	IsAuditSuccess() bool
	IsAuditFailure() bool
}

// Console is an object instance used to log auditing information on console
type Console struct{}

// Audit will perform auditing over console
func (c *Console) Audit(granted bool, ace Auditable) {
	if granted && ace.IsAuditSuccess() {
		fmt.Printf("Granted due to ACE %s", ace)
	} else if !granted && ace.IsAuditFailure() {
		fmt.Printf("Denied due to ACE %s", ace)
	}
}

// New will create a new console logger
func New() *Console {
	return &Console{}
}
