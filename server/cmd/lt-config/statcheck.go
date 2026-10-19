package main

import "os"

type fileState int

const (
	fileMissing fileState = iota
	fileExists
	fileUnknown
	fileNotRegular
)

func statFileState(path string) (fileState, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fileMissing, nil
		}
		return fileUnknown, err
	}
	return fileExists, nil
}

func statRegularFileState(path string) (fileState, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileMissing, nil
		}
		return fileUnknown, err
	}
	if !info.Mode().IsRegular() {
		return fileNotRegular, nil
	}
	return fileExists, nil
}

type backupAction int

const (
	backupRestore backupAction = iota
	backupDrop
	backupKeep
)

func decideLeftoverBackup(state fileState) backupAction {
	switch state {
	case fileExists:
		return backupDrop
	case fileUnknown:
		return backupKeep
	default:
		return backupRestore
	}
}

type recoveryAction int

const (
	recoveryFromBackup recoveryAction = iota
	recoveryCheckTarget
	recoveryKeep
)

func decideBatchBackup(state fileState) recoveryAction {
	switch state {
	case fileExists:
		return recoveryFromBackup
	case fileUnknown:
		return recoveryKeep
	default:
		return recoveryCheckTarget
	}
}
