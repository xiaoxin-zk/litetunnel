package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const portAllocAttempts = 5

func isPortConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrPortInUse) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unique") && !strings.Contains(msg, "duplicate key") {
		return false
	}
	return strings.Contains(msg, "remote_port")
}

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

func describeTunnelWriteError(err error) error {
	if err == nil {
		return nil
	}
	if !isPortConflict(err) && isNameConflict(err) {
		return fmt.Errorf("%w: 隧道名已存在，请换一个名字", ErrInvalidParam)
	}
	return err
}

func (s *Services) unavailablePorts() (map[int]struct{}, error) {
	out := make(map[int]struct{})
	for p := range ParsePortList(s.Settings.Get(KeyPortReserved)) {
		out[p] = struct{}{}
	}
	listening, err := listeningPortSet()
	if err != nil {
		return out, err
	}
	for key := range listening {
		i := strings.IndexByte(key, '|')
		if i < 0 {
			continue
		}
		if p, err := strconv.Atoi(key[i+1:]); err == nil {
			out[p] = struct{}{}
		}
	}
	return out, nil
}

func (s *Services) allocatePort(tx *gorm.DB, userID uint) (int, error) {
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
	blocked, scanErr := s.unavailablePorts()
	if scanErr != nil {
		return 0, fmt.Errorf("%w: %v", ErrPortScanUnavailable, scanErr)
	}
	for p := range blocked {
		set[p] = struct{}{}
	}

	start, end := s.Cfg.PortRangeStart, s.Cfg.PortRangeEnd
	span := end - start + 1
	if span <= 0 {
		return 0, ErrNoPortAvailable
	}
	offset, err := randomOffset(span)
	if err != nil {
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

func randomOffset(span int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func (s *Services) assertPortFree(tx *gorm.DB, port int) error {
	if port < s.Cfg.PortRangeStart || port > s.Cfg.PortRangeEnd {
		return fmt.Errorf("%w: 端口需在 %d-%d 范围内", ErrInvalidParam, s.Cfg.PortRangeStart, s.Cfg.PortRangeEnd)
	}
	blocked, scanErr := s.unavailablePorts()
	if _, hit := blocked[port]; hit {
		return fmt.Errorf("%w: 端口 %d 为保留端口或已被系统占用，请换一个", ErrPortInUse, port)
	}
	if scanErr != nil {
		return fmt.Errorf("%w: %v", ErrPortScanUnavailable, scanErr)
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
