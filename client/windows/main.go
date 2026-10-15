// Command LiteTunnel 是 Windows 桌面客户端。
//
// 客户端不内置任何服务器地址：首次启动由用户填写，凭据与配置保存在
// %AppData%\LiteTunnel 下，frpc.toml 由控制面下发并自动同步。
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "LiteTunnel 客户端",
		Width:     1040,
		Height:    720,
		MinWidth:  920,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 245, G: 247, B: 251, A: 1},
		OnStartup:        app.startup,
		// 关闭窗口时必须显式停掉 frpc：
		// Windows 上父进程退出不会结束子进程，不处理的话用户点 X 之后
		// frpc.exe 会继续在后台跑，端口仍被占用、隧道仍在转发。
		OnShutdown: app.shutdown,
		Bind: []any{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
		},
	})
	if err != nil {
		log.Fatalf("客户端启动失败: %v", err)
	}
}
