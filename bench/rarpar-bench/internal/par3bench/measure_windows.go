//go:build windows

package par3bench

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procGetProcessIoCounters    = kernel32.NewProc("GetProcessIoCounters")
	procK32GetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	procSetProcessAffinityMask  = kernel32.NewProc("SetProcessAffinityMask")
)

const (
	processQueryInformation = 0x0400
	processSetInformation   = 0x0200
	// ERROR_VIRUS_INFECTED and ERROR_VIRUS_DELETED: Defender (or another AV
	// filter) refused to start the image.
	errorVirusInfected = syscall.Errno(225)
	errorVirusDeleted  = syscall.Errno(226)
)

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func pinnedCommand(command Command) (string, []string, string) {
	return command.Path, command.Args, ""
}

// PinSupported reports whether --pin-cpus can take effect on this host.
func PinSupported() bool { return true }

// probe holds a process handle taken right after start. The process object
// stays queryable after exit for as long as the handle is open, which is how
// the I/O and peak-memory counters of an exited child are read.
type probe struct {
	handle syscall.Handle
	pinned string
}

func attachProbe(cmd *exec.Cmd, pin string) probe {
	if cmd.Process == nil {
		return probe{}
	}
	handle, err := syscall.OpenProcess(processQueryInformation|processSetInformation, false, uint32(cmd.Process.Pid))
	if err != nil {
		return probe{}
	}
	p := probe{handle: handle}
	if mask, ok := affinityMask(pin); ok {
		// The child is already running when the mask lands: process start-up
		// takes a few milliseconds before any benchmark work, and Go exposes no
		// suspended-start handle to close that window entirely.
		if r, _, _ := procSetProcessAffinityMask.Call(uintptr(handle), mask); r != 0 {
			p.pinned = pin
		}
	}
	return p
}

func (p probe) finish(measurement *Measurement) {
	if p.handle == 0 {
		return
	}
	defer syscall.CloseHandle(p.handle)
	var counters ioCounters
	if r, _, _ := procGetProcessIoCounters.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&counters))); r != 0 {
		measurement.ReadOps = int64(counters.ReadOperationCount)
		measurement.WriteOps = int64(counters.WriteOperationCount)
		measurement.OtherOps = int64(counters.OtherOperationCount)
		measurement.ReadBytes = int64(counters.ReadTransferCount)
		measurement.WriteBytes = int64(counters.WriteTransferCount)
	}
	var memory processMemoryCounters
	memory.CB = uint32(unsafe.Sizeof(memory))
	if r, _, _ := procK32GetProcessMemoryInfo.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&memory)), uintptr(memory.CB)); r != 0 {
		measurement.MaxRSSBytes = int64(memory.PeakWorkingSetSize)
	}
}

func fillRusage(*Measurement, *os.ProcessState) {}

// affinityMask turns "0-7" (or "3") into a processor mask.
func affinityMask(pin string) (uintptr, bool) {
	if pin == "" {
		return 0, false
	}
	low, high, found := strings.Cut(pin, "-")
	if !found {
		high = low
	}
	first, err1 := strconv.Atoi(low)
	last, err2 := strconv.Atoi(high)
	if err1 != nil || err2 != nil || first < 0 || last < first || last >= 64 {
		return 0, false
	}
	var mask uintptr
	for cpu := first; cpu <= last; cpu++ {
		mask |= 1 << uint(cpu)
	}
	return mask, true
}

func isQuarantineError(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == errorVirusInfected || errno == errorVirusDeleted
	}
	return false
}

func rssSource() string {
	return "K32GetProcessMemoryInfo PeakWorkingSetSize on the held process handle"
}
