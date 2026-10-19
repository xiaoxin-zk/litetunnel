//go:build embedfrpc

package main

import _ "embed"

//go:embed assets/frpc.exe
var embeddedFrpc []byte
