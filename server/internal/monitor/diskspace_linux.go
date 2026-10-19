//go:build linux

package monitor

import "syscall"

func diskUsage(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	if total > free {
		used = total - free
	}
	return total, used
}
