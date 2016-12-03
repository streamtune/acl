package domain

import "github.com/streamtune/acl"

// AuthoritySid is a Sid implementation holding a granted authority
type AuthoritySid string

// Equals will check if the receiver is equal to provided Sid implementation
func (s AuthoritySid) Equals(other acl.Sid) bool {
	if o, ok := other.(AuthoritySid); ok {
		return s.authority == o.authority
	}
	return false
}

// GetAuthority retrieve the authority for the receiver authority Sid.
func (s AuthoritySid) GetAuthority() string {
	return s
}

// PrincipalSid is a Sid implementation holding a principal
type PrincipalSid string

// Equals will check if the receiver is equal to provided Sid implementation
func (p PrincipalSid) Equals(other acl.Sid) bool {
	if o, ok := other.(PrincipalSid); ok {
		return p.principal == o.principal
	}
	return false
}

// GetPrincipal retrieve the principal for the receiver principal Sid.
func (p PrincipalSid) GetPrincipal() string {
	return p
}

// DefaultSidRetrievalStrategy is a basic implementation of SidRetrievalStrategy that creates a Sid for the principal, as
// well as every granted authority the principal holds.
type DefaultSidRetrievalStrategy struct {
	// TODO optionally provide a role hierarchy
}

// NewDefaultSidRetrievalStrategy will create a new SidRetrievalStrategyImpl instance
func NewDefaultSidRetrievalStrategy() *DefaultSidRetrievalStrategy {
	return &DefaultSidRetrievalStrategy{}
}

// GetSids will retrieve the sids for given authentication object
func (s *DefaultSidRetrievalStrategy) GetSids(auth acl.Authentication) []acl.Sid {
	roles := auth.GetAuthorities()
	sids := make([]acl.Sid, len(roles)+1)
	sids = append(sids, PrincipalSid(auth.GetPrincipal()))
	for _, role := range roles {
		sids = append(sids, AuthoritySid(role))
	}
	return sids
}
