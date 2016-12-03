package domain

import "github.com/streamtune/acl"

// Acl is the implementation class of acl.Instance interface
type Acl struct {
	id           interface{}
	oid          acl.Identity
	owner        acl.Sid
	parent       acl.Instance
	authStrategy AuthorizationStrategy
	permStrategy acl.PermissionGrantingStrategy
	aces         []acl.Ace
	inherits     bool
	loadedSids   []acl.Sid
}

func NewAcl(oid acl.Identity, id interface{}, auth AuthorizationStrategy, log AuditLogger) *Acl {
	return &Acl{
		oid:          oid,
		id:           id,
		authStrategy: auth,
		//permStrategy: NewDefaultPermissionGrantingStrategy(log),
	}
}

/*
	/**
	 * Full constructor, which should be used by persistence tools that do not provide
	 * field-level access features.
	 *
	 * @param objectIdentity the object identity this ACL relates to
	 * @param id the primary key assigned to this ACL
	 * @param aclAuthorizationStrategy authorization strategy
	 * @param grantingStrategy the {@code PermissionGrantingStrategy} which will be used
	 * by the {@code isGranted()} method
	 * @param parentAcl the parent (may be may be {@code null})
	 * @param loadedSids the loaded SIDs if only a subset were loaded (may be {@code null}
	 * )
	 * @param entriesInheriting if ACEs from the parent should inherit into this ACL
	 * @param owner the owner (required)
	 *
	public AclImpl(ObjectIdentity objectIdentity, Serializable id,
			AclAuthorizationStrategy aclAuthorizationStrategy,
			PermissionGrantingStrategy grantingStrategy, Acl parentAcl,
			List<Sid> loadedSids, boolean entriesInheriting, Sid owner) {
		Assert.notNull(objectIdentity, "Object Identity required");
		Assert.notNull(id, "Id required");
		Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
		Assert.notNull(owner, "Owner required");

		this.objectIdentity = objectIdentity;
		this.id = id;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
		this.parentAcl = parentAcl; // may be null
		this.loadedSids = loadedSids; // may be null
		this.entriesInheriting = entriesInheriting;
		this.owner = owner;
		this.permissionGrantingStrategy = grantingStrategy;
	}

	/**
	 * Private no-argument constructor for use by reflection-based persistence tools along
	 * with field-level access.
	 *
	@SuppressWarnings("unused")
	private AclImpl() {
	}

	// ~ Methods
	// ========================================================================================================

	public void deleteAce(int aceIndex) throws NotFoundException {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_GENERAL);
		verifyAceIndexExists(aceIndex);

		synchronized (aces) {
			this.aces.remove(aceIndex);
		}
	}

	private void verifyAceIndexExists(int aceIndex) {
		if (aceIndex < 0) {
			throw new NotFoundException("aceIndex must be greater than or equal to zero");
		}
		if (aceIndex >= this.aces.size()) {
			throw new NotFoundException(
					"aceIndex must refer to an index of the AccessControlEntry list. "
							+ "List size is " + aces.size() + ", index was " + aceIndex);
		}
	}

	public void insertAce(int atIndexLocation, Permission permission, Sid sid,
			boolean granting) throws NotFoundException {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_GENERAL);
		Assert.notNull(permission, "Permission required");
		Assert.notNull(sid, "Sid required");
		if (atIndexLocation < 0) {
			throw new NotFoundException(
					"atIndexLocation must be greater than or equal to zero");
		}
		if (atIndexLocation > this.aces.size()) {
			throw new NotFoundException(
					"atIndexLocation must be less than or equal to the size of the AccessControlEntry collection");
		}

		AccessControlEntryImpl ace = new AccessControlEntryImpl(null, this, sid,
				permission, granting, false, false);

		synchronized (aces) {
			this.aces.add(atIndexLocation, ace);
		}
	}

	public List<AccessControlEntry> getEntries() {
		// Can safely return AccessControlEntry directly, as they're immutable outside the
		// ACL package
		return new ArrayList<AccessControlEntry>(aces);
	}

	public Serializable getId() {
		return this.id;
	}

	public ObjectIdentity getObjectIdentity() {
		return objectIdentity;
	}

	public boolean isEntriesInheriting() {
		return entriesInheriting;
	}

	/**
	 * Delegates to the {@link PermissionGrantingStrategy}.
	 *
	 * @throws UnloadedSidException if the passed SIDs are unknown to this ACL because the
	 * ACL was only loaded for a subset of SIDs
	 * @see DefaultPermissionGrantingStrategy
	 *
	public boolean isGranted(List<Permission> permission, List<Sid> sids,
			boolean administrativeMode) throws NotFoundException, UnloadedSidException {
		Assert.notEmpty(permission, "Permissions required");
		Assert.notEmpty(sids, "SIDs required");

		if (!this.isSidLoaded(sids)) {
			throw new UnloadedSidException("ACL was not loaded for one or more SID");
		}

		return permissionGrantingStrategy.isGranted(this, permission, sids,
				administrativeMode);
	}

	public boolean isSidLoaded(List<Sid> sids) {
		// If loadedSides is null, this indicates all SIDs were loaded
		// Also return true if the caller didn't specify a SID to find
		if ((this.loadedSids == null) || (sids == null) || (sids.size() == 0)) {
			return true;
		}

		// This ACL applies to a SID subset only. Iterate to check it applies.
		for (Sid sid : sids) {
			boolean found = false;

			for (Sid loadedSid : loadedSids) {
				if (sid.equals(loadedSid)) {
					// this SID is OK
					found = true;

					break; // out of loadedSids for loop
				}
			}

			if (!found) {
				return false;
			}
		}

		return true;
	}

	public void setEntriesInheriting(boolean entriesInheriting) {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_GENERAL);
		this.entriesInheriting = entriesInheriting;
	}

	public void setOwner(Sid newOwner) {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_OWNERSHIP);
		Assert.notNull(newOwner, "Owner required");
		this.owner = newOwner;
	}

	public Sid getOwner() {
		return this.owner;
	}

	public void setParent(Acl newParent) {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_GENERAL);
		Assert.isTrue(newParent == null || !newParent.equals(this),
				"Cannot be the parent of yourself");
		this.parentAcl = newParent;
	}

	public Acl getParentAcl() {
		return parentAcl;
	}

	public void updateAce(int aceIndex, Permission permission) throws NotFoundException {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_GENERAL);
		verifyAceIndexExists(aceIndex);

		synchronized (aces) {
			AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(aceIndex);
			ace.setPermission(permission);
		}
	}

	public void updateAuditing(int aceIndex, boolean auditSuccess, boolean auditFailure) {
		aclAuthorizationStrategy.securityCheck(this,
				AclAuthorizationStrategy.CHANGE_AUDITING);
		verifyAceIndexExists(aceIndex);

		synchronized (aces) {
			AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(aceIndex);
			ace.setAuditSuccess(auditSuccess);
			ace.setAuditFailure(auditFailure);
		}
	}

	public boolean equals(Object obj) {
		if (obj instanceof AclImpl) {
			AclImpl rhs = (AclImpl) obj;
			if (this.aces.equals(rhs.aces)) {
				if ((this.parentAcl == null && rhs.parentAcl == null)
						|| (this.parentAcl != null && this.parentAcl
								.equals(rhs.parentAcl))) {
					if ((this.objectIdentity == null && rhs.objectIdentity == null)
							|| (this.objectIdentity != null && this.objectIdentity
									.equals(rhs.objectIdentity))) {
						if ((this.id == null && rhs.id == null)
								|| (this.id != null && this.id.equals(rhs.id))) {
							if ((this.owner == null && rhs.owner == null)
									|| (this.owner != null && this.owner
											.equals(rhs.owner))) {
								if (this.entriesInheriting == rhs.entriesInheriting) {
									if ((this.loadedSids == null && rhs.loadedSids == null)) {
										return true;
									}
									if (this.loadedSids != null
											&& (this.loadedSids.size() == rhs.loadedSids
													.size())) {
										for (int i = 0; i < this.loadedSids.size(); i++) {
											if (!this.loadedSids.get(i).equals(
													rhs.loadedSids.get(i))) {
												return false;
											}
										}
										return true;
									}
								}
							}
						}
					}
				}
			}
		}
		return false;
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("AclImpl[");
		sb.append("id: ").append(this.id).append("; ");
		sb.append("objectIdentity: ").append(this.objectIdentity).append("; ");
		sb.append("owner: ").append(this.owner).append("; ");

		int count = 0;

		for (AccessControlEntry ace : aces) {
			count++;

			if (count == 1) {
				sb.append("\n");
			}

			sb.append(ace).append("\n");
		}

		if (count == 0) {
			sb.append("no ACEs; ");
		}

		sb.append("inheriting: ").append(this.entriesInheriting).append("; ");
		sb.append("parent: ").append(
				(this.parentAcl == null) ? "Null" : this.parentAcl.getObjectIdentity()
						.toString());
		sb.append("; ");
		sb.append("aclAuthorizationStrategy: ").append(this.aclAuthorizationStrategy)
				.append("; ");
		sb.append("permissionGrantingStrategy: ").append(this.permissionGrantingStrategy);
		sb.append("]");

		return sb.toString();
	}
*/
