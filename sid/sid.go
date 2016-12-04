package sid

import (
	"context"
	"errors"
	"fmt"
)

// Sid is the interface exposed by sids
type Sid interface {
	Equals(Sid) bool
}

// Principal is a Sid holding a principal.
type Principal struct {
	principal string
}

// NewPrincipal will create a new Sid for given principal
func NewPrincipal(principal string) *Principal {
	return &Principal{principal}
}

// Equals will check if the provided principal is equal to this one
func (p *Principal) Equals(other Sid) bool {
	if o, ok := other.(*Principal); ok {
		return p.principal == o.principal
	}
	return false
}

// GetPrincipal will retrieve the principal
func (p *Principal) GetPrincipal() string {
	return p.principal
}

func (p *Principal) String() string {
	return fmt.Sprintf("Principal[%s]", p.principal)
}

// Authority is a Sid holding a granted authority.
type Authority struct {
	authority string
}

// NewAuthority will create a new Sid for the provided authority
func NewAuthority(authority string) *Authority {
	return &Authority{authority}
}

// Equals will check if the receiver is an Authority and has the same authority name
func (a *Authority) Equals(other Sid) bool {
	if o, ok := other.(*Authority); ok {
		return a.authority == o.authority
	}
	return false
}

// GetAuthority will retrieve the authority name
func (a *Authority) GetAuthority() string {
	return a.authority
}

func (a *Authority) String() string {
	return fmt.Sprintf("Authority[%s]", a.authority)
}

// Authentication is the object from which can be created a list of Sid
type Authentication interface {
	GetPrincipal() string
	GetAuthorities() []string
}

// New will create a new slice of Sid from provided authentication object
func New(auth Authentication) ([]Sid, error) {
	if auth == nil {
		return nil, errors.New("No sid available for nil authentication object")
	}
	authorities := auth.GetAuthorities()
	sids := make([]Sid, len(authorities)+1)
	sids = append(sids, NewPrincipal(auth.GetPrincipal()))
	for _, authority := range authorities {
		sids = append(sids, NewAuthority(authority))
	}
	return sids, nil
}

// NewFromContext wil extract a list of Sid from context
func NewFromContext(ctx context.Context) ([]Sid, error) {
	if auth, ok := ctx.Value("Authentication").(Authentication); ok {
		return New(auth)
	}
	return nil, fmt.Errorf("No authentication object found on context %x", ctx)
}
