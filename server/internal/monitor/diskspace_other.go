//go:build !linux

package monitor

func diskUsage(string) (total, used uint64) { return 0, 0 }
