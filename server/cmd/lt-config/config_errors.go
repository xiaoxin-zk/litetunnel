package main

import "errors"

type errKind int

const (
	kindConfig errKind = iota
	kindHost
	kindInternal
)

type classError struct {
	kind errKind
	err  error
}

func (e *classError) Error() string { return e.err.Error() }
func (e *classError) Unwrap() error { return e.err }

func hostError(err error) error     { return &classError{kind: kindHost, err: err} }
func internalError(err error) error { return &classError{kind: kindInternal, err: err} }

func classifyError(err error) errKind {
	var ce *classError
	if errors.As(err, &ce) {
		return ce.kind
	}
	return kindConfig
}
