//go:build darwin || linux

package safety

import (
	"fmt"
	"os"
	"syscall"
)

func Identity(info os.FileInfo) (device, id string, hardlink bool, sparse *bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", false, nil
	}
	s := st.Blocks*512 < info.Size()
	return fmt.Sprint(st.Dev), fmt.Sprintf("%d:%d", st.Dev, st.Ino), st.Nlink > 1, &s
}

func Owned(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}
