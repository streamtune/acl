package sid

import (
	"context"
	"errors"
	"fmt"
)

// DefaultRetriever is the default Sid retriever
var DefaultRetriever Retriever

func init() {
	DefaultRetriever = &defaultRetriever{}
}

// Sid is a security identity recognised by the ACL system.
//
// This interface provides indirection between actual security objects (eg principals, roles, groups etc) and what is
// stored inside an Acl. This is because an Acl will not store an entire security object, but only an abstraction of it.
// This interface therefore provides a simple way to compare these abstracted security identities with other security
// identities and actual security objects.
type Sid interface {
	// The name of sid
	Name() string
	// Equals will check if the receiver Sid object is equal to other one
	Equals(Sid) bool
}

// Retriever is a strategy interface that provides an ability to determine the Sid instances applicable for a Context.
type Retriever interface {
	// Retrieve the available Sid for given context
	Retrieve(context.Context) ([]Sid, error)
}

type principal struct {
	name string
}

func (p principal) Name() string {
	return p.name
}

func (p principal) Equals(other Sid) bool {
	if o, ok := other.(principal); ok {
		return p.name == o.name
	}
	return false
}

func (p principal) String() string {
	return fmt.Sprintf("PrincipalSid[%s]", p.name)
}

// ForPrincipal will create a new Sid for the provided name
func ForPrincipal(name string) (Sid, error) {
	if name == "" {
		return nil, errors.New("Cannot create Sid from an empty principal")
	}
	return &principal{name}, nil
}

type authority struct {
	name string
}

func (a authority) Name() string {
	return a.name
}

func (a authority) Equals(other Sid) bool {
	if o, ok := other.(authority); ok {
		return a.name == o.name
	}
	return false
}

func (a authority) String() string {
	return fmt.Sprintf("AuthoritySid[%s]", a.name)
}

// ForAuthority will create a new Sid for given authority
func ForAuthority(name string) (Sid, error) {
	if name == "" {
		return nil, errors.New("Cannot create Sid from an empty authority")
	}
	return &authority{name}, nil
}

type authentication interface {
	GetPrincipal() string
	GetAuthorities() []string
}

type defaultRetriever struct{}

func (r *defaultRetriever) Retrieve(ctx context.Context) ([]Sid, error) {
	if auth, ok := ctx.Value("Authentication").(authentication); ok {
		authorities := auth.GetAuthorities()
		sids := make([]Sid, len(authorities)+1)
		sid, err := ForPrincipal(auth.GetPrincipal())
		if err != nil {
			return nil, err
		}
		sids = append(sids, sid)
		for _, authority := range authorities {
			sid, err = ForAuthority(authority)
			if err != nil {
				return nil, err
			}
			sids = append(sids, sid)
		}
		return sids, nil
	}
	return nil, fmt.Errorf("No authentication object found on context %x", ctx)
}

// Retrieve the sid from provided context using the DefaultRetriever
func Retrieve(ctx context.Context) ([]Sid, error) {
	return DefaultRetriever.Retrieve(ctx)
}
