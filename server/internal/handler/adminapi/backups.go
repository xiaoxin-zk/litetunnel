package adminapi

import (
	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

func (h *Handler) ListBackups(c *gin.Context) {
	items, err := h.svc.ListBackups()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"items":     items,
		"supported": h.svc.BackupSupported(),
		"dir":       h.svc.BackupDir(),
	})
}

func (h *Handler) CreateBackup(c *gin.Context) {
	file, err := h.svc.CreateBackup("")
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "backup.create", "backup", file.Name, "手动创建备份")
	httpx.OK(c, file)
}

func (h *Handler) DownloadBackup(c *gin.Context) {
	name := c.Param("name")
	path, err := h.svc.BackupFilePath(name)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "backup.download", "backup", name, "下载备份")
	c.FileAttachment(path, name)
}

func (h *Handler) DeleteBackup(c *gin.Context) {
	name := c.Param("name")
	if err := h.svc.DeleteBackup(name); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "backup.delete", "backup", name, "删除备份")
	httpx.OK(c, gin.H{"message": "已删除"})
}

// RestoreBackup 恢复后立即重启：现有连接还持有旧库的数据页，不重启会读到不一致的状态。
func (h *Handler) RestoreBackup(c *gin.Context) {
	name := c.Param("name")
	if err := h.svc.RestoreBackup(name); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "backup.restore", "backup", name, "从备份恢复数据库")
	httpx.OK(c, gin.H{"restoring": true, "message": "已恢复，正在重启面板"})
	h.svc.RestartPanel()
}
