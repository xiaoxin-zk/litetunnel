package main

import "strings"

var buildServerURL = ""

var buildVersion = "dev"

func Version() string {
	if v := strings.TrimSpace(buildVersion); v != "" {
		return v
	}
	return "dev"
}

func defaultServerURL() string {
	return strings.TrimRight(strings.TrimSpace(buildServerURL), "/")
}

func serverFixed() bool {
	return defaultServerURL() != ""
}
