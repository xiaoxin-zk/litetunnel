package service

import (
	"gorm.io/gorm"
)

// AdminDeleteUser 删除用户及其全部隧道与流量记录。
//
// 本函数只保留「编排」：在用户锁内跑事务，然后做善后。具体步骤分别见
// account_lifecycle.go 的 accountPurgeTx 与 purgeAccountAfterCommit——
// 管理员删除与自助注销共用这两段，避免两条路径各维护一份而慢慢走偏
// （缺陷 1 就是这么来的：善后步骤被复制成两份，加断流时容易漏掉一边）。
func (s *Services) AdminDeleteUser(id uint) error {
	ports, err := s.deleteUserTx(id)
	if err != nil {
		return err
	}
	s.purgeAccountAfterCommit(id, ports)
	return nil
}

// deleteUserTx 在用户锁内完成删号事务，返回需要回收的端口清单。
//
// 锁只罩住事务，用 defer 释放：
//   - 事务提交之后账号行已经不存在，建隧道不可能再成功，锁没有继续占着的理由；
//   - 善后里的断流要访问 frps 管理接口（最长十几秒），而断流实现
//     （proxy_drain.go 的 closeDrainedProxy）内部按代理逐条取**同一把**用户锁
//     ——持锁调用会自死锁（sync.Mutex 不可重入）；
//   - 用 defer 而不是「提交后手写 Unlock」：事务回调里一旦 panic，手写的那行
//     永远执行不到，这把分片锁会被永久占住，之后落到同一分片的所有建隧道/
//     删号请求全部挂死。
func (s *Services) deleteUserTx(id uint) ([]portProto, error) {
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	var ports []portProto
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		// 管理员删除不需要复核密码：调用方已通过管理端鉴权。
		// 账号不存在时 accountPurgeTx 内部已统一成 ErrNotFound。
		ports, err = accountPurgeTx(tx, id, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ports, nil
}
