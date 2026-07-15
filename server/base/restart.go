package base

import (
	"os"
	"strconv"
	"syscall"
)

func RestartProcess() error {
	app, err := os.Executable()
	if err != nil {
		return err
	}
	// 关闭所有非标准 fd（fd > 2），确保 tun/tap 设备被释放
	// syscall.Exec 不执行 defer，water 库创建的 tun fd 没有 O_CLOEXEC，会残留在新进程中
	closeNonStdFDs()
	return syscall.Exec(app, os.Args, os.Environ())
}

func closeNonStdFDs() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		syscall.Close(fd)
	}
}
