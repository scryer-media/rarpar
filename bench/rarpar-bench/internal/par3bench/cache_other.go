//go:build !linux

package par3bench

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// DropCaches is Linux-only.
func DropCaches() error { return errors.New("dropping the page cache is Linux-only") }

// DropCachesSupported reports why DropCaches cannot work here.
func DropCachesSupported() (bool, string) {
	return false, "dropping the page cache is Linux-only, not " + runtime.GOOS
}

// LoadAverage is the 1-minute load average from sysctl vm.loadavg on macOS
// and the BSDs (0 elsewhere or when unreadable).
func LoadAverage() float64 {
	if runtime.GOOS == "windows" {
		return 0
	}
	output, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0
	}
	return parseLoadAverage(strings.Trim(strings.TrimSpace(string(output)), "{} "))
}
