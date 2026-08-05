package bench

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func CollectMachine(ctx context.Context, label, docker string) Machine {
	machine := Machine{
		Label:        label,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		Filesystem:   "not-collected",
	}
	machine.Kernel = commandLine(ctx, "uname", "-sr")
	if machine.Kernel == "" {
		machine.Kernel = "not-collected"
	}
	machine.CPU = commandLine(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
	if machine.CPU == "" {
		machine.CPU = commandLine(ctx, "uname", "-m")
	}
	if machine.CPU == "" {
		machine.CPU = "not-collected"
	}
	machine.DockerVersion = commandLine(ctx, docker, "version", "--format", "{{.Server.Version}}")
	machine.MemoryBytes = memoryBytes(ctx)
	machine.Filesystem = filesystemType(ctx)
	machine.GPU = "not-probed"
	return machine
}

func memoryBytes(ctx context.Context) uint64 {
	if runtime.GOOS == "darwin" {
		value, err := strconv.ParseUint(commandLine(ctx, "sysctl", "-n", "hw.memsize"), 10, 64)
		if err == nil {
			return value
		}
	}
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/meminfo")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "MemTotal:" {
					value, parseErr := strconv.ParseUint(fields[1], 10, 64)
					if parseErr == nil {
						return value * 1024
					}
				}
			}
		}
	}
	return 0
}

func filesystemType(ctx context.Context) string {
	if runtime.GOOS == "darwin" {
		if value := commandLine(ctx, "stat", "-f", "%T", "."); value != "" {
			return value
		}
	}
	if runtime.GOOS == "linux" {
		if value := commandLine(ctx, "stat", "-f", "-c", "%T", "."); value != "" {
			return value
		}
	}
	return "not-collected"
}

func commandLine(ctx context.Context, program string, args ...string) string {
	output, err := exec.CommandContext(ctx, program, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func Preflight(ctx context.Context, docker string) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is required: %w", err)
	}
	if _, err := exec.LookPath(docker); err != nil {
		return fmt.Errorf("Docker is required for corpus generation: %w", err)
	}
	if err := exec.CommandContext(ctx, docker, "info").Run(); err != nil {
		return fmt.Errorf("Docker is unavailable: %w", err)
	}
	return nil
}
