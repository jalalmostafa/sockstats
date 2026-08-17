package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v3/process"
)

func GetProcessChildren(pid uint) (PidList, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}

	parent_tgid, err := p.Tgid()
	if err != nil {
		return nil, err
	}

	children, err := p.Children()
	if err != nil {
		return nil, err
	}

	var pids PidList
	for _, child := range children {
		tgid, err := child.Tgid()
		if err != nil {
			return nil, err
		}
		if tgid != parent_tgid {
			pids = append(pids, uint(child.Pid))
		}
	}
	return pids, nil
}

func WaitProgram(pid int) (bool, int) {
	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, &rusage)

	if wpid == pid && err == nil && ws.Exited() {
		return true, ws.ExitStatus()
	}

	return false, -1
}

func TerminateProgram(pid uint) error {
	process, err := os.FindProcess(int(pid))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	if err = process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}

		if err := process.Kill(); err != nil {
			return err
		}
	}

	return nil
}

func ReadSymbolAddress(symbol string) (uint64, error) {
	kallsyms, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return 0, err
	}
	symbols := strings.Split(string(kallsyms), "\n")
	for _, line := range symbols {
		parts := strings.Split(line, " ")
		if parts[2] == symbol {
			return strconv.ParseUint(parts[0], 16, 64)
		}

	}

	return 0, errors.New("Symbol " + symbol + " Not Found")
}
