//go:build windows

package tray

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

//go:embed app.ico
var appIconICO []byte

type Callbacks struct {
	OnOpen      func()
	OnRecheck   func()
	OnTrip      func()
	OnQuit      func()
}

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW      = user32.NewProc("RegisterClassExW")
	procCreateWindowExW       = user32.NewProc("CreateWindowExW")
	procDefWindowProcW        = user32.NewProc("DefWindowProcW")
	procGetMessageW           = user32.NewProc("GetMessageW")
	procTranslateMessage      = user32.NewProc("TranslateMessage")
	procDispatchMessageW      = user32.NewProc("DispatchMessageW")
	procPostQuitMessage       = user32.NewProc("PostQuitMessage")
	procDestroyWindow         = user32.NewProc("DestroyWindow")
	procLoadImageW            = user32.NewProc("LoadImageW")
	procCreatePopupMenu       = user32.NewProc("CreatePopupMenu")
	procAppendMenuW           = user32.NewProc("AppendMenuW")
	procTrackPopupMenu        = user32.NewProc("TrackPopupMenu")
	procDestroyMenu           = user32.NewProc("DestroyMenu")
	procGetCursorPos          = user32.NewProc("GetCursorPos")
	procSetForegroundWindow   = user32.NewProc("SetForegroundWindow")
	procShellNotifyIconW      = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW      = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmApp         = 0x8000
	wmTrayIcon    = wmApp + 1
	wmDestroy     = 0x0002
	wmCommand     = 0x0111
	wmLButtonUp   = 0x0202
	wmRButtonUp   = 0x0205
	wmLButtonDbl  = 0x0203

	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nifMessage    = 0x00000001
	nifIcon       = 0x00000002
	nifTip        = 0x00000004

	imageIcon     = 1
	lrLoadFromFile = 0x00000010
	mfString      = 0x00000000
	mfSeparator   = 0x00000800
	tpmRightBtn   = 0x0002
	tpmReturnCmd  = 0x0100

	cmdOpen    = 1001
	cmdRecheck = 1002
	cmdTrip    = 1003
	cmdQuit    = 1004
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct {
	x, y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
}

type Manager struct {
	hwnd uintptr
	nid  notifyIconDataW
	cb   Callbacks
	icoPath string
}

var activeMgr *Manager

func Run(tooltip string, cb Callbacks) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	m := &Manager{cb: cb}
	activeMgr = m

	hInst, _, _ := procGetModuleHandleW.Call(0)
	clsName, _ := syscall.UTF16PtrFromString("ClaudeEnvCheckTrayWindow")
	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     hInst,
		lpszClassName: clsName,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(clsName)), uintptr(unsafe.Pointer(clsName)),
		0, 0, 0, 0, 0, 0, 0, hInst, 0,
	)
	m.hwnd = hwnd

	// Write embedded .ico to temp file for LoadImageW
	icoPath := filepath.Join(os.TempDir(), "claude-env-check-tray.ico")
	if os.WriteFile(icoPath, appIconICO, 0o600) == nil {
		m.icoPath = icoPath
	}
	icoPtr, _ := syscall.UTF16PtrFromString(icoPath)
	hIcon, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(icoPtr)), imageIcon, 32, 32, lrLoadFromFile)

	m.nid = notifyIconDataW{
		cbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		hWnd:             hwnd,
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: wmTrayIcon,
		hIcon:            hIcon,
	}
	setTip(&m.nid, tooltip)
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&m.nid)))

	var message msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
	}
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&m.nid)))
	if m.icoPath != "" {
		_ = os.Remove(m.icoPath)
	}
}

func UpdateTooltip(tooltip string) {
	if activeMgr == nil || activeMgr.hwnd == 0 {
		return
	}
	setTip(&activeMgr.nid, tooltip)
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&activeMgr.nid)))
}

func Quit() {
	if activeMgr != nil && activeMgr.hwnd != 0 {
		procDestroyWindow.Call(activeMgr.hwnd)
	}
}

func setTip(nid *notifyIconDataW, s string) {
	u16, _ := syscall.UTF16FromString(s)
	for i := range nid.szTip {
		nid.szTip[i] = 0
	}
	for i := 0; i < len(u16) && i < len(nid.szTip)-1; i++ {
		nid.szTip[i] = u16[i]
	}
}

func showMenu(hwnd uintptr) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	appendStr := func(id uintptr, label string) {
		p, _ := syscall.UTF16PtrFromString(label)
		procAppendMenuW.Call(hMenu, mfString, id, uintptr(unsafe.Pointer(p)))
	}
	appendStr(cmdOpen, "打开控制台 (Claude 环境体检)")
	appendStr(cmdRecheck, "立即复检出口")
	appendStr(cmdTrip, "紧急手动熔断")
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendStr(cmdQuit, "退出并恢复配置")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(hMenu, tpmRightBtn|tpmReturnCmd, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
	handleCommand(cmd)
}

func handleCommand(cmd uintptr) {
	if activeMgr == nil {
		return
	}
	switch cmd {
	case cmdOpen:
		if activeMgr.cb.OnOpen != nil {
			go activeMgr.cb.OnOpen()
		}
	case cmdRecheck:
		if activeMgr.cb.OnRecheck != nil {
			go activeMgr.cb.OnRecheck()
		}
	case cmdTrip:
		if activeMgr.cb.OnTrip != nil {
			go activeMgr.cb.OnTrip()
		}
	case cmdQuit:
		if activeMgr.cb.OnQuit != nil {
			activeMgr.cb.OnQuit()
		}
		procDestroyWindow.Call(activeMgr.hwnd)
	}
}

func wndProc(hwnd uintptr, uMsg uint32, wParam, lParam uintptr) uintptr {
	switch uMsg {
	case wmTrayIcon:
		switch uint32(lParam) {
		case wmLButtonDbl, wmLButtonUp:
			if activeMgr != nil && activeMgr.cb.OnOpen != nil {
				go activeMgr.cb.OnOpen()
			}
		case wmRButtonUp:
			showMenu(hwnd)
		}
		return 0
	case wmCommand:
		handleCommand(wParam & 0xFFFF)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(uMsg), wParam, lParam)
	return ret
}
