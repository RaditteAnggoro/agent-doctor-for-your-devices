//go:build !darwin && !linux

package platforms

func Disk(path string) (*int64, *int64) { return nil, nil }
