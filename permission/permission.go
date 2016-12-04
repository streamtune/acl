package permission

import "bytes"

// Permission represents a permission granted to a sid.Sid for a given domain object.
type Permission uint32

// NoPermission is used to provide no permission
// ReadPermission is used in order to read a value
// WritePermission is used in order to write a value
// CreatePermisssion is used in order to create a new value
// DeletePermission is used in order to delete a value
// AdministrationPermission is used in order to allow administration tasks
const (
	NoPermission   Permission = 0
	ReadPermission Permission = 1 << iota
	WritePermission
	CreatePermisssion
	DeletePermission
	AdministrationPermission
)

// Match will check that a permission match another one
func (p Permission) Match(other Permission) bool {
	return p&other != 0
}

// HasFlag check that a Permission hold a specific flag
func (p Permission) HasFlag(flag uint32) bool {
	return p&(1<<flag) != 0
}

// Set returns a new Permission with the provided flag set
func (p Permission) Set(flag uint32) Permission {
	return p | (1 << flag)
}

// Clear returns a new Permission with the provided flag unset
func (p Permission) Clear(flag uint32) Permission {
	return p & ^(1 << flag)
}

// Toggle returns a new Permission with the provided flag toggled
func (p Permission) Toggle(flag uint32) Permission {
	return p ^ (1 << flag)
}

// Convert a Permission to a string
func (p Permission) String() string {
	res := bytes.NewBuffer(make([]byte, 0, 32))
	for i := 0; i < 32; i++ {
		if p.HasFlag(uint32(i)) {
			res.WriteRune('*')
		} else {
			res.WriteRune('.')
		}
	}
	return res.String()
}
