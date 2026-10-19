package main

import (
	"fmt"
	"io"
	"os"
)

const (
	maxConfigInputBytes = 1 << 20
)

func readConfigInput(path string) ([]byte, error) {
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

	if fi2, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi2.Mode().IsRegular() {
		return nil, &inputFileError{path: path, kind: fi2.Mode().Type().String()}
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxConfigInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigInputBytes {
		return nil, &inputFileTooLargeError{path: path, size: int64(len(raw))}
	}
	return raw, nil
}

type inputFileError struct {
	path string
	kind string
}

func (e *inputFileError) Error() string {
	return fmt.Sprintf("%s 不是普通文件（%s）：拒绝读取。请把它换成真实文件，或修正符号链接指向", e.path, e.kind)
}

type inputFileTooLargeError struct {
	path string
	size int64
}

func (e *inputFileTooLargeError) Error() string {
	return fmt.Sprintf("%s 大小为 %d 字节，超过 %d 字节上限：拒绝读取（文件可能已损坏或被替换）",
		e.path, e.size, maxConfigInputBytes)
}
