//go:build windows

package workbench

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const runRegKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "ClaudeEnvCheck"

func IsAutoStartEnabled() bool {
	cmd := exec.Command("reg", "query", runRegKey, "/v", runValueName)
	out, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(out), runValueName)
}

func SetAutoStartEnabled(enabled bool) error {
	if !enabled {
		_ = exec.Command("reg", "delete", runRegKey, "/v", runValueName, "/f").Run()
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	val := fmt.Sprintf(`"%s" --silent`, exe)
	return exec.Command("reg", "add", runRegKey, "/v", runValueName, "/t", "REG_SZ", "/d", val, "/f").Run()
}

func OpenURL(u string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
}
