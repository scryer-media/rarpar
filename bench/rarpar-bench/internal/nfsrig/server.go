package nfsrig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

// ServerKind names the server implementation in every result row.
const ServerKind = "kernel-nfsd"

// NFSv4 grace and lease times the server starts with. The grace period holds
// every OPEN after nfsd starts; the kernel's 90 s default would only delay the
// first run, and 10 s is the kernel's floor.
const (
	graceSeconds = "10"
	leaseSeconds = "10"
)

// Server runs the kernel NFS server inside a privileged container until ctx
// ends: it loads nfsd, writes the exports, starts rpcbind, mountd and nfsd,
// writes a provenance marker into every export root, and marks itself ready
// for the compose health check. It tears the server down on the way out.
func Server(ctx context.Context, config ServerConfig, log io.Writer) error {
	exports := Exports()
	step := func(name string, args ...string) error {
		fmt.Fprintf(log, "nfs server: %s %s\n", name, strings.Join(args, " "))
		output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err := step("modprobe", "nfsd"); err != nil {
		return fmt.Errorf("the kernel has no usable nfsd (the compose file bind-mounts /lib/modules): %w", err)
	}
	if !mounted("/proc/fs/nfsd") {
		if err := step("mount", "-t", "nfsd", "nfsd", "/proc/fs/nfsd"); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/var/lib/nfs/v4recovery", "/run/rpcbind"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{"nfsv4gracetime": graceSeconds, "nfsv4leasetime": leaseSeconds} {
		// Settable only while nfsd is stopped; a failure leaves the default.
		if err := os.WriteFile(filepath.Join("/proc/fs/nfsd", name), []byte(value), 0o644); err != nil {
			fmt.Fprintf(log, "nfs server: %s left at the default: %v\n", name, err)
		}
	}
	kernel := strings.TrimSpace(readText("/proc/sys/kernel/osrelease"))
	for _, export := range exports {
		if err := os.MkdirAll(export.Path, 0o777); err != nil {
			return err
		}
		marker := ServerMarker{
			Kind: ServerKind, Kernel: kernel, Export: export, Config: config,
			ExportOptions: exportOptions(export),
			BackingFS:     backingFS(export.Path),
		}
		data, err := json.MarshalIndent(marker, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(export.Path, MarkerName), append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/etc/exports", []byte(ExportsFile(exports)), 0o644); err != nil {
		return err
	}
	defer teardown(log)
	for _, command := range [][]string{
		{"rpcbind", "-w"},
		{"exportfs", "-ra"},
		{"rpc.mountd"},
		append([]string{"rpc.nfsd"}, config.NFSDArgs()...),
	} {
		if err := step(command[0], command[1:]...); err != nil {
			return err
		}
	}
	if err := step("exportfs", "-v"); err != nil {
		return err
	}
	if err := os.WriteFile(ReadyFile, []byte(kernel+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(log, "nfs server: %s on %s serving %s with %d threads\n", ServerKind, kernel, strings.Join(config.Versions, ","), config.Threads)
	<-ctx.Done()
	return nil
}

// exportOptions is the export's own line of the exports file, minus its path.
func exportOptions(export Export) string {
	for _, line := range strings.Split(ExportsFile([]Export{export}), "\n") {
		if path, options, ok := strings.Cut(line, " "); ok && path == export.Path {
			return strings.TrimSpace(options)
		}
	}
	return ""
}

// teardown stops nfsd in this network namespace so a stopped container leaves
// no server threads behind in the shared kernel.
func teardown(log io.Writer) {
	_ = os.Remove(ReadyFile)
	for _, command := range [][]string{{"rpc.nfsd", "0"}, {"exportfs", "-ua"}, {"pkill", "rpc.mountd"}, {"pkill", "rpcbind"}} {
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			fmt.Fprintf(log, "nfs server: teardown %s: %v %s\n", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
		}
	}
	fmt.Fprintln(log, "nfs server: stopped")
}

// Ready is the compose health check.
func Ready() error {
	if _, err := os.Stat(ReadyFile); err != nil {
		return errors.New("nfs server not ready")
	}
	return nil
}

func readText(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// mounted reports whether path is a mount point in this mount namespace.
func mounted(path string) bool {
	mount, ok := par3bench.MountFor(par3bench.ParseMountInfo(readText("/proc/self/mountinfo")), path)
	return ok && mount.MountPoint == path
}

// backingFS is the filesystem type of the mount holding path.
func backingFS(path string) string {
	mount, _ := par3bench.MountFor(par3bench.ParseMountInfo(readText("/proc/self/mountinfo")), path)
	return mount.FSType
}
