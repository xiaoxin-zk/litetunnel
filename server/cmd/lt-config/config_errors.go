package main

import "errors"

// 本文件给 renderAndApply 的错误标注 HTTP 语义，handleRender 据此决定状态码。
//
// 三类失败对管理页的意义完全不同，混在一个状态码里会让界面无法区分
// 「改配置」与「查服务」：
//
//   - 配置错误（422）：提交的值本身不对（校验不通过、渲染失败），
//     管理员在原位改完重试即可；
//   - 宿主机错误（502）：docker 不可用、镜像拉取失败、重建容器失败，
//     得去查宿主机的 docker 服务；
//   - 内部错误（500）：配置已通过校验，但读盘/写盘失败，需要看本服务日志。
type errKind int

const (
	kindConfig errKind = iota
	kindHost
	kindInternal
)

// classError 给一个错误标注 HTTP 语义，底层错误原样可读、可 Unwrap。
type classError struct {
	kind errKind
	err  error
}

func (e *classError) Error() string { return e.err.Error() }
func (e *classError) Unwrap() error { return e.err }

func hostError(err error) error     { return &classError{kind: kindHost, err: err} }
func internalError(err error) error { return &classError{kind: kindInternal, err: err} }

// classifyError 取回错误类别；未标注的按配置错误（422）处理——
// renderAndApply 里大部分直接返回的正是「配置不对」这一类错误。
func classifyError(err error) errKind {
	var ce *classError
	if errors.As(err, &ce) {
		return ce.kind
	}
	return kindConfig
}
