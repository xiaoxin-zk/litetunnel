package main

// 本文件是「读取部署目录里的输入文件」的统一入口：.env、模板、
// docker-compose.yml 都从这里读。
//
// # 为什么要统一
//
// 这三个文件都是**运维可置换**的输入，而读取它们的代码分散在 dotenv.go、
// compose_image.go、apply.go 三处，各自 os.ReadFile。分散带来两个真实问题：
//
//   - 没有大小上限。一个被写坏（或被人替换成 /dev/zero）的文件会让
//     os.ReadFile 一直分配内存，进程被 OOM 杀掉——表现为「面板莫名其妙
//     重启」，而日志里什么都没有。
//   - 没有文件类型策略。FIFO 会让 Read 永久阻塞（读取端没有写者时），
//     设备文件则会无限产出字节；符号链接本身不是问题，但它必须最终
//     解析到一个**普通文件**，否则上面两条就会以更隐蔽的方式出现。
//
// # 符号链接策略（显式写清楚，避免以后各说各话）
//
//   - 读：允许符号链接，但解析后的目标必须是普通文件，且大小不超过上限。
//     部署里把 .env 指向密码管理目录下的实体文件是常见做法，一刀切拒绝会
//     让这些部署直接起不来。
//   - 写：不允许目标是符号链接（见 validateManagedPaths）。写入是
//     「临时文件 + rename」，rename 会替换掉链接本身而不是它的目标，
//     结果是一份看不出异常的新文件躺在原地、真实目标仍是旧内容——这类
//     半成功状态比直接报错难查得多。
import (
	"fmt"
	"io"
	"os"
)

const (
	// maxConfigInputBytes 是单个输入文件的读取上限。
	//
	// 1 MiB 对 .env / frps.toml / Caddyfile / docker-compose.yml 都远超实际
	// 需要（最大的一份是十几 KB 的模板），足够容纳任何正常的手工改动，
	// 同时让「被替换成大文件」这类故障变成一条明确的错误。
	maxConfigInputBytes = 1 << 20
)

// readConfigInput 读取一个输入文件，拒绝非普通文件与超限文件。
//
// 返回的错误信息里说明的是「这个文件为什么不能读」，而不是底层的
// EISDIR/EINVAL：管理员需要的是「把 .env 换成真实文件」，不是系统调用名。
func readConfigInput(path string) ([]byte, error) {
	// Stat（而不是 Lstat）跟随符号链接：策略是「最终目标必须是普通文件」，
	// 链接本身合法。悬空链接、链接环在这里会以 Stat 错误的形式暴露。
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, &inputFileError{path: path, kind: fi.Mode().Type().String()}
	}
	if fi.Size() > maxConfigInputBytes {
		return nil, &inputFileTooLargeError{path: path, size: fi.Size()}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 再核一次类型：Stat 与 Open 之间文件可能被换掉（TOCTOU）。这一步挡不住
	// 有权限的攻击者，但能让「读到一半被替换」这种事故留下明确的错误。
	if fi2, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi2.Mode().IsRegular() {
		return nil, &inputFileError{path: path, kind: fi2.Mode().Type().String()}
	}

	// 多读一个字节用于判断「是否刚好超限」：LimitReader 读到上限就返回
	// EOF，无法区分「正好等于上限」与「远超上限」。
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigInputBytes {
		return nil, &inputFileTooLargeError{path: path, size: int64(len(raw))}
	}
	return raw, nil
}

// inputFileError 表示输入路径不是普通文件。
type inputFileError struct {
	path string
	kind string
}

func (e *inputFileError) Error() string {
	return fmt.Sprintf("%s 不是普通文件（%s）：拒绝读取。请把它换成真实文件，或修正符号链接指向", e.path, e.kind)
}

// inputFileTooLargeError 表示输入文件超过读取上限。
type inputFileTooLargeError struct {
	path string
	size int64
}

func (e *inputFileTooLargeError) Error() string {
	return fmt.Sprintf("%s 大小为 %d 字节，超过 %d 字节上限：拒绝读取（文件可能已损坏或被替换）",
		e.path, e.size, maxConfigInputBytes)
}
