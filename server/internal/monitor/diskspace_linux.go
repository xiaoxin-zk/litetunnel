//go:build linux

package monitor

import "syscall"

// diskUsage 返回路径所在文件系统的总容量与已用量。
//
// 这里必须做平台分离（而不是像读 /proc 那样直接写）：
// 读 /proc 是**运行期**的 Linux 专有行为——代码在 Windows 上照样编译，
// 只是执行时拿不到数据；而 syscall.Statfs 是**编译期**的 Linux 专有符号，
// 不分平台就会导致整个包在非 Linux 上编译失败。
//
// 面板生产环境只跑在 Linux 容器里，所以非 Linux 的兜底实现只是为了让
// 开发者在自己的笔记本上也能编译通过。
func diskUsage(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	// 用 Bfree 而不是 Bavail：Bavail 是「非特权用户可用」，
	// 与它算出的已用量会比 `df` 多出那部分保留块，两个数字对不上
	// 会让管理员怀疑监控不准。
	free := st.Bfree * uint64(st.Bsize)
	if total > free {
		used = total - free
	}
	return total, used
}
