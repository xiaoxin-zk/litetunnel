package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// portAllocAttempts 是自动分配端口撞车后的最大尝试次数。
//
// 取 5 是权衡：随机撞车的概率本身很低（池子越大越低），5 次几乎不可能全部
// 撞上；而真撞上 5 次说明池子已经接近占满，继续重试也没意义。
const portAllocAttempts = 5

// isPortConflict 判断错误是否来自「该端口已被别人占用」。
//
// 两种来源：端口唯一索引冲突，以及建隧道前的复核（assertPortFree）。
// 后者是「加锁前挑好的候选端口在进事务前被抢走」的必然结果。
//
// 两个驱动的报错文本不同，但都会带上端口这个标识：
//
//	SQLite     ：UNIQUE constraint failed: lt_tunnels.remote_port
//	PostgreSQL ：duplicate key value violates unique constraint "idx_lt_tunnels_remote_port"
//
// 判定必须**同时**要求「是唯一约束」和「提到端口」，只认前者会把名称冲突
// 也算进来（见 isNameConflict）：那种冲突重试再多次也还是同一个错误，
// 却会在日志里留下 5 行「端口分配撞车」——把排查方向直接带到错的地方。
func isPortConflict(err error) bool {
	if err == nil {
		return false
	}
	// 建隧道前会复核候选端口是否仍空着（见 createTunnelLocked）：加锁之前
	// 读到的候选可能已被并发请求占掉。这与唯一索引冲突是同一件事的两种
	// 表现，自动分配路径应当换个端口重试，而不是把错误直接抛给用户。
	if errors.Is(err, ErrPortInUse) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unique") && !strings.Contains(msg, "duplicate key") {
		return false
	}
	return strings.Contains(msg, "remote_port")
}

// isNameConflict 判断错误是否来自「同一用户下隧道名重复」（user_id + name）。
//
// 排除法是刻意的：PG 的报错里往往只有索引名，而索引名是建表时定的
//（idx_user_tunnel），靠它反而更脆；带上 remote_port 的一定是端口冲突，
// 剩下的唯一约束冲突就只可能是名字。
func isNameConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unique") && !strings.Contains(msg, "duplicate key") {
		return false
	}
	return !strings.Contains(msg, "remote_port")
}

// describeTunnelWriteError 把唯一索引冲突翻译成用户看得懂的错误。
//
// 数据库原文（UNIQUE constraint failed: lt_tunnels.user_id, lt_tunnels.name）
// 对用户没有任何意义，原样往上抛只会变成一句「服务内部错误，请稍后重试」，
// 而用户真正需要知道的是「换个隧道名」。
func describeTunnelWriteError(err error) error {
	if err == nil {
		return nil
	}
	if !isPortConflict(err) && isNameConflict(err) {
		return fmt.Errorf("%w: 隧道名已存在，请换一个名字", ErrInvalidParam)
	}
	return err
}

// allocatePort 从端口池中**随机**分配一个未占用端口。
//
// 起点用随机数，而不是「按用户 ID 派生起点 + 顺序扫描」：
//
//   - 顺序分配时端口是**可预测**的。同一用户每次拿到的都是池里靠前的第一个
//     空位，连续创建几条隧道就能把用到的整段端口推出来；换端口也一样。
//     端口可预测会明显降低外部扫描/撞库的成本，而端口对外就是服务入口。
//   - 随机起点同样能避免并发碰撞：两个请求几乎不可能从同一个位置开始扫，
//     真正撞上时由下面的唯一索引兜底。
//
// 依赖 lt_tunnels(remote_port) 上的部分唯一索引做最终兜底：
// 即使并发分配撞车，也会由数据库拒绝，不会出现端口冲突。
func (s *Services) allocatePort(tx *gorm.DB, userID uint) (int, error) {
	// 必须统计全部用户（含自己）已占用的端口，否则会给同一用户重复分配。
	var used []int
	if err := tx.Model(&model.Tunnel{}).
		Where("remote_port > 0").
		Pluck("remote_port", &used).Error; err != nil {
		return 0, err
	}
	set := make(map[int]struct{}, len(used))
	for _, p := range used {
		set[p] = struct{}{}
	}

	start, end := s.Cfg.PortRangeStart, s.Cfg.PortRangeEnd
	span := end - start + 1
	if span <= 0 {
		return 0, ErrNoPortAvailable
	}
	offset, err := randomOffset(span)
	if err != nil {
		// 取不到随机数（几乎不可能）：退回按用户分散，至少不会让所有用户
		// 都从同一个位置开始扫。
		offset = int(userID) % span
	}
	for i := 0; i < span; i++ {
		p := start + (offset+i)%span
		if _, ok := set[p]; !ok {
			return p, nil
		}
	}
	return 0, ErrNoPortAvailable
}

// randomOffset 返回 [0, span) 内的一个随机数。
//
// 用 crypto/rand 而不是 math/rand：这里要的是「外部猜不到」，而不只是
// 「分布均匀」——math/rand 的全局序列是可预测的，知道种子就能算出下一条
// 隧道会拿到哪个端口。
func randomOffset(span int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

// assertPortFree 校验指定端口是否可用。
func (s *Services) assertPortFree(tx *gorm.DB, port int) error {
	if port < s.Cfg.PortRangeStart || port > s.Cfg.PortRangeEnd {
		return fmt.Errorf("%w: 端口需在 %d-%d 范围内", ErrInvalidParam, s.Cfg.PortRangeStart, s.Cfg.PortRangeEnd)
	}
	var n int64
	if err := tx.Model(&model.Tunnel{}).Where("remote_port = ?", port).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrPortInUse
	}
	return nil
}
