package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v4/process"
)

var socketInodeRe = regexp.MustCompile(`^socket:\[(\d+)\]$`)

const ANON_INODE = "anon_inode:[eventpoll]"

func parseUnixSockets() ([]uint64, error) {
	content, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return nil, err
	}

	lines := slices.Collect(strings.Lines(string(content)))
	inodes := make([]uint64, len(lines)-1)

	for _, line := range lines[1:] {
		parts := strings.Fields(line)
		inode, err := strconv.ParseUint(parts[6], 10, 64)
		if err != nil {
			return nil, err
		}
		inodes = append(inodes, inode)
	}

	return inodes, nil
}

func GetProcessSocketInodes(pid uint) (map[uint32]uint64, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fdDir, err)
	}

	unix_inodes, err := parseUnixSockets()
	if err != nil {
		return nil, err
	}

	result := make(map[uint32]uint64)
	for _, entry := range entries {
		fdNum, err := strconv.Atoi(entry.Name())
		if err != nil {
			return nil, err
		}

		linkPath := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			return nil, err
		}

		if m := socketInodeRe.FindStringSubmatch(target); m != nil {
			inode, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				return nil, err
			}

			if slices.Contains(unix_inodes, inode) {
				continue
			}

			result[uint32(fdNum)] = inode
		} else if target == ANON_INODE {
			info, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fdNum))
			if err != nil {
				return nil, err
			}

			fstat := info.Sys().(*syscall.Stat_t)
			result[uint32(fdNum)] = fstat.Ino
		}
	}

	return result, nil
}

func GetProcessChildren(pid uint) (PidList, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}

	parent_tgid, err := p.Tgid()
	if err != nil {
		return nil, err
	}

	pids := make(PidList)
	fdinodes, err := GetProcessSocketInodes(pid)
	if err != nil {
		return nil, err
	}

	pids.Add(pid, fdinodes)

	children, err := p.Children()
	if err == process.ErrorNoChildren {
		return pids, nil
	}

	if err != nil {
		return nil, err
	}

	for _, child := range children {
		tgid, err := child.Tgid()
		if err != nil {
			return nil, err
		}
		if tgid != parent_tgid {
			child_pid := uint(child.Pid)
			fdinodes, err := GetProcessSocketInodes(child_pid)
			if err != nil {
				return nil, err
			}
			pids.Add(child_pid, fdinodes)
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
