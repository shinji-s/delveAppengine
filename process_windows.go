// +build windows

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Windows API functions
var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
)

// Some constants from the Windows API
const (
	ERROR_NO_MORE_FILES = 0x12
	MAX_PATH            = 260
)

// PROCESSENTRY32 is the Windows API structure that contains a process's
// information.
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid       int
	ppid      int
	exe       string
	startTime uint64
	done      bool
	zombie    bool
}

// Pid () returns pid of the process
func (p *WindowsProcess) Pid() int {
	return p.pid
}

// Ppid () return parent process id
func (p *WindowsProcess) PPid() int {
	return p.ppid
}

// Executable () returns path of the binary
func (p *WindowsProcess) Executable() string {
	return p.exe
}

func newWindowsProcess(e *PROCESSENTRY32) *WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return &WindowsProcess{
		pid:  int(e.ProcessID),
		ppid: int(e.ParentProcessID),
		exe:  syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func findProcess(pid int) (Process, error) {
	ps, err := processes()
	if err != nil {
		return nil, err
	}

	for _, p := range ps {
		if p.Pid() == pid {
			return p, nil
		}
	}

	return nil, nil
}

func processes() ([]Process, error) {
	handle, _, _ := procCreateToolhelp32Snapshot.Call(
		0x00000002,
		0)
	if handle < 0 {
		return nil, syscall.GetLastError()
	}
	defer procCloseHandle.Call(handle)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Error retrieving process info.")
	}

	results := make([]Process, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return results, nil
}

// StartTime returns process Start time
func (p *WindowsProcess) StartTime() (uint64, error) {
	if p.done {
		return p.startTime, nil
	}
	var err error
	p.startTime, p.zombie, err = getProcessStartTime(p.Pid())
	p.done = true
	return p.startTime, err
}

// Zombie returns if the process is a zombie process
func (p *WindowsProcess) Zombie() (bool, error) {
	if p.done {
		return p.zombie, nil
	}
	var err error
	p.startTime, p.zombie, err = getProcessStartTime(p.Pid())
	p.done = true
	return p.zombie, err
}

//return the start time and a bool indicating if the process is Zombie
func getProcessStartTime(pid int) (uint64, bool, error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	defer syscall.CloseHandle(handle)
	if err != nil {
		return 0, false, err
	}
	var u syscall.Rusage
	var e = syscall.GetProcessTimes(syscall.Handle(handle),
		&u.CreationTime, &u.ExitTime, &u.KernelTime, &u.UserTime)

	var nano int64 = u.CreationTime.Nanoseconds()
	return uint64(time.Unix(0, nano).Local().UnixNano()),
		false, e
}

func binaryContainsMagicKey(pid int, key string) bool {
	return true
}
