package service

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrBackupUnsupported = errors.New("当前数据库不支持在线备份：SQLite 可直接备份，PostgreSQL 请用 pg_dump 定期导出")
	ErrBackupNotFound    = errors.New("备份文件不存在")
	ErrBackupNameInvalid = errors.New("备份文件名不合法")
)

const (
	backupNamePrefix   = "litetunnel-"
	backupPreRestore   = "-pre-restore"
	backupTimeLayout   = "20060102-150405"
	backupAutoInterval = 24 * time.Hour
)

var backupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.db$`)

type BackupFile struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
	PreRestore bool      `json:"pre_restore"`
}

// BackupDir 默认放在数据库同级的 backups/ 目录，容器部署时随数据卷一起持久化。
func (s *Services) BackupDir() string {
	if v := strings.TrimSpace(os.Getenv("LT_BACKUP_DIR")); v != "" {
		return v
	}
	if s.Cfg.DBDriver == "sqlite" {
		if dir := filepath.Dir(s.Cfg.DBDSN); dir != "" && dir != "." {
			return filepath.Join(dir, "backups")
		}
	}
	return filepath.Join(".", "data", "backups")
}

func (s *Services) BackupSupported() bool { return s.Cfg.DBDriver == "sqlite" }

func (s *Services) backupPath(name string) (string, error) {
	if !backupNameRe.MatchString(name) || filepath.Base(name) != name {
		return "", ErrBackupNameInvalid
	}
	return filepath.Join(s.BackupDir(), name), nil
}

func (s *Services) ListBackups() ([]BackupFile, error) {
	entries, err := os.ReadDir(s.BackupDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupFile{}, nil
		}
		return nil, err
	}
	out := make([]BackupFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupFile{
			Name:       e.Name(),
			Size:       info.Size(),
			CreatedAt:  info.ModTime(),
			PreRestore: strings.Contains(e.Name(), backupPreRestore),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// CreateBackup 用 VACUUM INTO 做热备：不锁写、产出的是单文件一致快照。
func (s *Services) CreateBackup(tag string) (BackupFile, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	return s.createBackupLocked(tag)
}

func (s *Services) createBackupLocked(tag string) (BackupFile, error) {
	if !s.BackupSupported() {
		return BackupFile{}, ErrBackupUnsupported
	}
	dir := s.BackupDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return BackupFile{}, fmt.Errorf("创建备份目录失败: %w", err)
	}
	// 文件名精确到毫秒并做重名检查：同一秒内连续备份不能互相覆盖。
	name := backupNamePrefix + time.Now().Format(backupTimeLayout) +
		fmt.Sprintf("-%03d", time.Now().Nanosecond()/1e6) + tag + ".db"
	path := filepath.Join(dir, name)
	for i := 1; ; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		name = fmt.Sprintf("%s%s-%03d-%d%s.db", backupNamePrefix,
			time.Now().Format(backupTimeLayout), time.Now().Nanosecond()/1e6, i, tag)
		path = filepath.Join(dir, name)
	}

	if err := s.DB.Exec("VACUUM INTO ?", path).Error; err != nil {
		// VACUUM INTO 需要 SQLite >= 3.27；老库退回「checkpoint + 拷贝」。
		_ = os.Remove(path)
		if err2 := s.copyDatabaseFile(path); err2 != nil {
			return BackupFile{}, fmt.Errorf("备份失败: %v（回退复制也失败：%v）", err, err2)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return BackupFile{}, err
	}
	if info.Size() == 0 {
		_ = os.Remove(path)
		return BackupFile{}, errors.New("备份文件为空，已删除")
	}

	s.purgeBackupsLocked()
	return BackupFile{
		Name: name, Size: info.Size(), CreatedAt: info.ModTime(),
		PreRestore: strings.Contains(name, backupPreRestore),
	}, nil
}

func (s *Services) copyDatabaseFile(target string) error {
	if err := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		return err
	}
	src, err := os.Open(s.Cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, err := os.Create(target)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

// purgeBackupsLocked 按保留份数清理旧备份；恢复前的安全备份不参与轮转。
func (s *Services) purgeBackupsLocked() {
	retention := 7
	if n := s.Settings.Int(KeyBackupRetention); n > 0 {
		retention = n
	}
	list, err := s.ListBackups()
	if err != nil {
		return
	}
	kept := 0
	for _, f := range list {
		if f.PreRestore {
			continue
		}
		kept++
		if kept <= retention {
			continue
		}
		path, err := s.backupPath(f.Name)
		if err != nil {
			continue
		}
		if err := os.Remove(path); err != nil {
			log.Printf("[backup] 清理旧备份 %s 失败: %v", f.Name, err)
		}
	}
}

// BackupFilePath 返回可下载的备份绝对路径，顺带做存在性与文件名校验。
func (s *Services) BackupFilePath(name string) (string, error) {
	path, err := s.backupPath(name)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", ErrBackupNotFound
		}
		return "", err
	}
	return path, nil
}

func (s *Services) DeleteBackup(name string) error {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	path, err := s.backupPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrBackupNotFound
		}
		return err
	}
	return nil
}

// RestoreBackup 先用当前库做一份 pre-restore 安全备份，再把备份覆盖回数据库文件。
// 调用方负责紧接着重启进程，否则现有连接仍持有旧的数据页。
func (s *Services) RestoreBackup(name string) error {
	// 与备份/删除串行：恢复过程中再插一次备份会覆盖正在使用的快照。
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	if !s.BackupSupported() {
		return ErrBackupUnsupported
	}
	src, err := s.backupPath(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(src); err != nil {
		return ErrBackupNotFound
	}

	if _, err := s.createBackupLocked(backupPreRestore); err != nil {
		return fmt.Errorf("恢复前的安全备份失败，已中止: %w", err)
	}
	if err := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		log.Printf("[backup] 恢复前 checkpoint 失败（继续尝试覆盖）: %v", err)
	}

	dst := s.Cfg.DBDSN
	tmp := dst + ".restore"
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.Create(tmp)
	if err != nil {
		_ = in.Close()
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	_ = in.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// 旧库的 WAL/SHM 必须一起丢掉，否则新库会被旧日志污染。
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dst + suffix); err != nil && !os.IsNotExist(err) {
			log.Printf("[backup] 清理 %s%s 失败: %v", dst, suffix, err)
		}
	}
	return nil
}

// maybeAutoBackup 由维护任务调用：距上次备份超过 24 小时就补一份。
func (s *Services) maybeAutoBackup(now time.Time) {
	if !s.BackupSupported() || !s.Settings.Bool(KeyBackupAuto) {
		return
	}
	list, err := s.ListBackups()
	if err != nil {
		log.Printf("[backup] 读取备份列表失败: %v", err)
		return
	}
	for _, f := range list {
		if f.PreRestore {
			continue
		}
		if now.Sub(f.CreatedAt) < backupAutoInterval {
			return
		}
		break
	}
	if _, err := s.CreateBackup(""); err != nil {
		log.Printf("[backup] 自动备份失败: %v", err)
	}
}
