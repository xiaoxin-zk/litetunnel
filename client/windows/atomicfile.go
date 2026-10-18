package main

import "os"

// writeFileAtomic 先写同目录临时文件、再原子替换目标。
//
// 直接覆盖的话，写到一半被强杀或断电会留下半截文件：客户端配置（frpc.toml）
// 残了会让 frpc 启动失败，本地配置（config.json）残了会被当成「没有配置」而
// 把用户登出。同目录 rename 在同一文件系统内是原子的（Windows 上 os.Rename
// 走 MoveFileEx + MOVEFILE_REPLACE_EXISTING，可直接替换已存在的目标）。
//
// perm 由调用方决定：含凭据的文件一律 0600。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
