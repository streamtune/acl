package acl

import "bytes"

func (f *Bitmask) hasFlag(flag Bitmask) bool {
	return *f&flag != 0
}

func (f *Bitmask) addFlag(flag Bitmask) {
	*f |= flag
}

func (f *Bitmask) removeFlag(flag Bitmask) {
	*f &= ^flag
}

func (f *Bitmask) toggleFlag(flag Bitmask) {
	*f ^= flag
}

func (f *Bitmask) removeAll() {
	*f = 0
}

func (f *Bitmask) String() string {
	res := bytes.NewBuffer(make([]byte, 0, 32))
	for i := 0; i < 32; i++ {
		if f.hasFlag(Bitmask(1 << uint32(i))) {
			res.WriteRune('*')
		} else {
			res.WriteRune('.')
		}
	}
	return res.String()
}
