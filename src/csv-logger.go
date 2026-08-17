package main

import (
	"errors"
	"fmt"
	"os"
)

type SocktraceEventLog struct {
	pids PidList
	file *os.File
}

func CreateEventLoggerWithHeaders(pids PidList) (*SocktraceEventLog, error) {
	var err error
	perf := new(SocktraceEventLog)
	perf.pids = pids
	path := fmt.Sprintf("socktrace-%v.csv", pids.String())

	perf.file, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	_, err = perf.file.WriteString("SocketCookie,ParentCookie,TimestampNS,PID,TGID,Syscall,FileDescriptor\n")
	if err != nil {
		return nil, err
	}

	err = perf.file.Sync()
	if err != nil {
		return nil, err
	}

	return perf, err
}

func (perf *SocktraceEventLog) WriteEvent(event *SocketEvent) error {
	if perf.file == nil {
		return errors.New("invalid file")
	}

	row := fmt.Sprintf("%d,%d,%d,%d,%d,%s,%d\n",
		event.Cookie, event.ParentCookie, event.TimestampNs,
		event.Pid, event.Tgid, socktrace_syscalls[event.Operation],
		event.FileDescriptor)

	_, err := perf.file.WriteString(row)
	if err != nil {
		err = perf.file.Sync()
	}

	return nil
}

func (perf *SocktraceEventLog) Close() error {
	if perf.file == nil {
		return errors.New("invalid file")
	}

	return perf.file.Close()
}
