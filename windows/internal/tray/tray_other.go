//go:build !windows

package tray

import (
	"os"
	"os/signal"
	"syscall"
)

type Callbacks struct {
	OnOpen    func()
	OnRecheck func()
	OnTrip    func()
	OnQuit    func()
}

var quitCh = make(chan struct{})

func Run(tooltip string, cb Callbacks) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-quitCh:
	}
	if cb.OnQuit != nil {
		cb.OnQuit()
	}
}

func UpdateTooltip(tooltip string) {}

func Quit() {
	select {
	case <-quitCh:
	default:
		close(quitCh)
	}
}
