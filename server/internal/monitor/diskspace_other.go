//go:build !linux

package monitor

// diskUsage 在非 Linux 平台返回 0，表示「未采集」。
//
// 返回 0 而不是伪造一个数字：前端对 0 的处理是「不显示磁盘容量卡片」，
// 而一个假数字会让开发者以为自己本地的磁盘真的快满了。
//
// 面板生产环境只跑在 Linux 容器里，这个分支只服务于本地开发构建。
func diskUsage(string) (total, used uint64) { return 0, 0 }
