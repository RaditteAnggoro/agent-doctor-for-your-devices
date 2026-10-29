//go:build darwin || linux

package platforms

import "syscall"

// Disk measures the current filesystem's visible capacity, not a whole disk.
func Disk(path string) (*int64, *int64) {
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return nil, nil
	}
	total := int64(s.Blocks) * int64(s.Bsize)
	available := int64(s.Bavail) * int64(s.Bsize)
	return &total, &available
}
