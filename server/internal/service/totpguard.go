package service

import (
	"log"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// ClaimTOTPStep 尝试占用某个管理员的一个动态口令步进码。
//
// 返回 false 表示这一步（或更早的步进）已经被用过，判定为重放。
//
// # 为什么记在数据库而不是内存表
//
// TOTP 校验本身只回答「这个码在当前窗口内是否有效」，而窗口是 ±1 步
// （最长 90 秒）。在这 90 秒里同一个 6 位口令可以提交任意多次。
//
// 现实中的攻击路径是**钓鱼反代**：
//
//	受害者 → 攻击者搭的假登录页 → 转发给真站
//	攻击者在这一刻同时拿到了密码和动态口令，
//	然后在窗口内用它们登录真站——即使受害者随后立刻改密码也来不及。
//
// 以前用内存 map 记录「已用口令」：控制面一重启（或请求被负载均衡到另一个
// 实例）记录就没了，同一个口令在窗口内又能通过一次。改成数据库条件更新之后，
// 判定既是**原子**的（只有比已记录的步进更新才能写入成功）又是**持久**的，
// 重启与多实例都不会丢。
//
// 登记粒度是「步进码」而不是「口令值」：步进码能精确区分窗口内的不同时刻
// （上一分钟的口令不该挡住这一分钟的），也不会把口令明文存下来。
func (s *Services) ClaimTOTPStep(adminID uint, step int64) bool {
	res := s.DB.Model(&model.Admin{}).
		Where("id = ? AND totp_last_step < ?", adminID, step).
		Update("totp_last_step", step)
	if res.Error != nil {
		// 数据库不可用时**拒绝**：防重放失效的后果（口令被重放）比一次
		// 登录失败严重得多，这里必须 fail-closed。
		log.Printf("[totp] 更新防重放步进失败（管理员 %d）: %v", adminID, res.Error)
		return false
	}
	// 条件没命中：这一步不比已记录的更新——重复提交同一个口令，
	// 或者提交了一个更早窗口的口令。
	return res.RowsAffected == 1
}
