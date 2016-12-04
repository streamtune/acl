package acl

import "github.com/streamtune/acl/oid"
import "sync"

// Cache is a caching layer for AclService
type Cache interface {
	// Evict an object from cache by primary key.
	EvictFromCacheByID(interface{})

	// Evict an object from cache by his object id.
	EvictFromCacheByOid(oid.Oid)

	// Retrieve an object from cache by primary key
	GetFromCacheByID(interface{}) (MutableAcl, bool)

	// Retrieve an object from cache by oid.
	GetFromCacheByOid(oid.Oid) (MutableAcl, bool)

	// Put a MutableAcl into cache
	PutInCache(MutableAcl)

	// Clear the cache
	ClearCache()
}

type defaultCache struct {
	sync.RWMutex
	idCache  map[interface{}]MutableAcl
	oidCache map[oid.Oid]MutableAcl
}

func newDefaultCache() *defaultCache {
	cache := new(defaultCache)
	cache.idCache = make(map[interface{}]MutableAcl)
	cache.oidCache = make(map[oid.Oid]MutableAcl)
	return cache
}

func (cache *defaultCache) EvictFromCacheByID(id interface{}) {
	cache.Lock()
	if acl, ok := cache.idCache[id]; ok {
		delete(cache.idCache, id)
		delete(cache.oidCache, acl.GetIdentity())
	}
	cache.Unlock()
}

func (cache *defaultCache) EvictFromCacheByOid(id oid.Oid) {
	cache.Lock()
	if acl, ok := cache.oidCache[id]; ok {
		delete(cache.oidCache, id)
		delete(cache.idCache, acl.GetID())
	}
	cache.Unlock()
}

func (cache *defaultCache) GetFromCacheByID(id interface{}) (MutableAcl, bool) {
	cache.RLock()
	acl, ok := cache.idCache[id]
	cache.RUnlock()
	return acl, ok
}

func (cache *defaultCache) GetFromCacheByOid(id oid.Oid) (MutableAcl, bool) {
	cache.RLock()
	acl, ok := cache.oidCache[id]
	cache.RUnlock()
	return acl, ok
}

func (cache *defaultCache) PutInCache(acl MutableAcl) {
	cache.Lock()
	cache.idCache[acl.GetID()] = acl
	cache.oidCache[acl.GetIdentity()] = acl
	cache.Unlock()
}

func (cache *defaultCache) ClearCache() {
	cache.Lock()
	cache.idCache = make(map[interface{}]MutableAcl)
	cache.oidCache = make(map[oid.Oid]MutableAcl)
	cache.Unlock()
}
