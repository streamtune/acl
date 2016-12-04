package security

// ChangeType is the type of change that can be applied to an Acl.
type ChangeType int

// ChangeOwnership is a change in ownership of Acl
// ChangeAuditing is a change of auditing behavior
// ChangeGeneral is any other type of change
const (
	ChangeOwnership ChangeType = iota
	ChangeAuditing
	ChangeGeneral
)
