package acl

import "bytes"

func (f *Permission) hasFlag(flag uint32) bool {
	return *f&(1<<flag) != 0
}

func (f *Permission) addFlag(flag uint32) {
	*f |= (1 << flag)
}

func (f *Permission) removeFlag(flag uint32) {
	*f &= ^(1 << flag)
}

func (f *Permission) toggleFlag(flag uint32) {
	*f ^= (1 << flag)
}

func (f *Permission) removeAll() {
	*f = 0
}

func (f *Permission) String() string {
	res := bytes.NewBuffer(make([]byte, 0, 32))
	for i := 0; i < 32; i++ {
		if f.hasFlag(Permission(1 << uint32(i))) {
			res.WriteRune('*')
		} else {
			res.WriteRune('.')
		}
	}
	return res.String()
}
