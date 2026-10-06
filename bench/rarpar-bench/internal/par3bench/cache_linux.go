//go:build linux

package par3bench

import (
	"os"
	"syscall"
)

// DropCaches writes back dirty pages and drops the clean page, dentry and
// inode caches, so the next run reads from storage (for NFS, from the server)
// instead of the client's memory. It needs root (a privileged container).
// The drop is host-wide: on a VM that also runs the NFS server, the server's
// cache goes too.
func DropCaches() error {
	syscall.Sync()
	return os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0o200)
}

// DropCachesSupported reports whether DropCaches can work here.
func DropCachesSupported() (bool, string) {
	file, err := os.OpenFile("/proc/sys/vm/drop_caches", os.O_WRONLY, 0)
	if err != nil {
		return false, "cannot open /proc/sys/vm/drop_caches for writing (needs root in a privileged container): " + err.Error()
	}
	file.Close()
	return true, ""
}

// LoadAverage is the 1-minute load average from /proc/loadavg (0 when
// unreadable). In a container it is the kernel's, so the VM's on a VM.
func LoadAverage() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	return parseLoadAverage(string(data))
}
