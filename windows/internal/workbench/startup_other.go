//go:build !windows

package workbench

func IsAutoStartEnabled() bool { return false }

func SetAutoStartEnabled(enabled bool) error { return nil }

func OpenURL(u string) {}
