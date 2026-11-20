package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/clipsone/claude-env-check/windows/internal/tray"
	"github.com/clipsone/claude-env-check/windows/internal/webui"
	"github.com/clipsone/claude-env-check/windows/internal/workbench"
)

const appVersion = "1.2.0"

func main() {
	silent := flag.Bool("silent", false, "Start silently in system tray and auto-start guard when proxy is ready")
	noBrowser := flag.Bool("no-browser", false, "Do not open dashboard browser automatically on launch")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Claude Environment Check (Windows) v%s\n", appVersion)
		return
	}

	engine := webui.NewEngine()
	url, err := engine.StartHTTPServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start local dashboard: %v\n", err)
		os.Exit(1)
	}

	if *silent {
		go engine.AutoStartGuardIfReady()
	} else if !*noBrowser {
		workbench.OpenURL(url)
	}

	tray.Run("Claude 环境体检 v"+appVersion, tray.Callbacks{
		OnOpen:    func() { workbench.OpenURL(url) },
		OnRecheck: func() { engine.RecheckGuard(false) },
		OnTrip:    func() { engine.ManualTrip() },
		OnQuit:    func() { engine.Shutdown() },
	})
}
