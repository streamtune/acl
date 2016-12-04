package change

// Type is the type of change that can be applied to an Acl.
type Type int

// Ownership is a change in ownership of Acl
// Auditing is a change of auditing behavior
// General is any other type of change
const (
	Ownership Type = iota
	Auditing
	General
)
