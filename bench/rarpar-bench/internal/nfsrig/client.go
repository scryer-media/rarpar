package nfsrig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

// localIOParameter is the NFS client's LOCALIO switch. With client and server
// on one kernel, LOCALIO hands I/O straight to the server's filesystem and
// skips the protocol, which would make the remote rows measure local disk.
const localIOParameter = "/sys/module/nfs/parameters/localio_enabled"

// ClientConfig is the client role's environment.
type ClientConfig struct {
	Server string      `json:"server"`
	Mount  MountConfig `json:"mount"`
	// Build compiles the candidate and engine_perf from the read-only source
	// tree into the cache volume (RIG_BUILD, default on).
	Build bool `json:"build"`
	// Reference builds the pinned par3cmdline into the cache volume when it
	// is not there yet (RIG_REFERENCE, default on).
	Reference bool `json:"reference"`
	// Ext4 is the size of a loop-mounted ext4 image to add as the
	// `local-ext4` target, in truncate(1) units ("8G"), or empty for none
	// (RIG_EXT4).
	Ext4 string `json:"ext4,omitempty"`
	// RateMBps throttles the client's link to the server to this many
	// megabytes a second each way, or 0 for none (RIG_RATE_MBPS).
	RateMBps int `json:"rate_mbps,omitempty"`
}

// ClientConfigFromEnv reads the client role's environment.
func ClientConfigFromEnv(getenv func(string) string) (ClientConfig, error) {
	mount, err := MountConfigFromEnv(getenv)
	if err != nil {
		return ClientConfig{}, err
	}
	config := ClientConfig{Server: "nfs-server", Mount: mount, Build: true, Reference: true}
	if text := getenv("NFS_SERVER"); text != "" {
		config.Server = text
	}
	for _, flag := range []struct {
		name  string
		value *bool
	}{{"RIG_BUILD", &config.Build}, {"RIG_REFERENCE", &config.Reference}} {
		switch text := getenv(flag.name); text {
		case "":
		case "0", "off":
			*flag.value = false
		case "1", "on":
			*flag.value = true
		default:
			return ClientConfig{}, fmt.Errorf("%s=%q: want on or off", flag.name, text)
		}
	}
	if text := getenv("RIG_EXT4"); text != "" {
		if !validSize(text) {
			return ClientConfig{}, fmt.Errorf("RIG_EXT4=%q: want a size such as 8G", text)
		}
		config.Ext4 = text
	}
	if text := getenv("RIG_RATE_MBPS"); text != "" {
		rate, err := strconv.Atoi(text)
		if err != nil || rate < 1 || rate > 100000 {
			return ClientConfig{}, fmt.Errorf("RIG_RATE_MBPS=%q: want megabytes a second, 1-100000", text)
		}
		config.RateMBps = rate
	}
	return config, nil
}

// validSize accepts a decimal count with an optional K, M, G or T suffix.
func validSize(text string) bool {
	digits := strings.TrimRight(text, "KMGT")
	if len(text)-len(digits) > 1 || digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Binaries are the client's built tools, all in the cache volume.
type Binaries struct {
	Candidate  string
	EnginePerf string
	Reference  string
}

// DefaultBinaries are where Build and BuildReference put the tools.
func DefaultBinaries() Binaries {
	return Binaries{
		Candidate:  filepath.Join(Cache, "target", "release", "rarpar"),
		EnginePerf: filepath.Join(Cache, "target", "release", "examples", "engine_perf"),
		Reference:  filepath.Join(Cache, "ref", "build", "par3cmd", "par3"),
	}
}

// Session is a mounted client. Close unmounts and restores LOCALIO.
type Session struct {
	Config ClientConfig
	// Markers are the server's provenance files, by target name.
	Markers map[string]ServerMarker
	// LocalFS is the filesystem type under the local control directory.
	LocalFS string
	// Ext4 says the `local-ext4` target is mounted.
	Ext4 bool
	// Link is the throttled link's measured throughput, when RateMBps is set.
	Link         *LinkCheck
	shaped       string
	loop         string
	localIOSaved string
	mounted      []string
	log          io.Writer
}

// Mount disables LOCALIO, mounts every export with the configured options
// and reads each export's marker.
func Mount(ctx context.Context, config ClientConfig, log io.Writer) (*Session, error) {
	session := &Session{Config: config, Markers: map[string]ServerMarker{}, log: log}
	if _, err := exec.LookPath("modprobe"); err == nil {
		_ = exec.CommandContext(ctx, "modprobe", "nfs").Run()
	}
	saved, err := os.ReadFile(localIOParameter)
	switch {
	case err == nil:
		session.localIOSaved = strings.TrimSpace(string(saved))
		want := "N"
		if config.Mount.LocalIO {
			want = "Y"
		}
		if err := os.WriteFile(localIOParameter, []byte(want), 0o644); err != nil {
			return nil, fmt.Errorf("set %s=%s (the client must be privileged): %w", localIOParameter, want, err)
		}
		fmt.Fprintf(log, "nfs client: localio %s -> %s\n", session.localIOSaved, want)
	case os.IsNotExist(err):
		// A kernel without LOCALIO has nothing to bypass.
		fmt.Fprintln(log, "nfs client: this kernel has no NFS LOCALIO")
	default:
		return nil, err
	}
	if config.RateMBps > 0 {
		iface, err := shape(ctx, config.RateMBps, log)
		session.shaped = iface
		if err != nil {
			session.Close()
			return nil, err
		}
		session.Link = &LinkCheck{Interface: iface, RateMBps: config.RateMBps}
	}
	options := config.Mount.Options()
	for _, export := range Exports() {
		if err := os.MkdirAll(export.MountPoint, 0o755); err != nil {
			session.Close()
			return nil, err
		}
		source := export.Source(config.Server, config.Mount.Version)
		fmt.Fprintf(log, "nfs client: mount -t nfs -o %s %s %s\n", options, source, export.MountPoint)
		output, err := exec.CommandContext(ctx, "mount", "-t", "nfs", "-o", options, source, export.MountPoint).CombinedOutput()
		if err != nil {
			session.Close()
			return nil, fmt.Errorf("mount %s: %w\n%s", source, err, strings.TrimSpace(string(output)))
		}
		session.mounted = append(session.mounted, export.MountPoint)
		data, err := os.ReadFile(filepath.Join(export.MountPoint, MarkerName))
		if err != nil {
			session.Close()
			return nil, fmt.Errorf("the export %s has no server marker: %w", source, err)
		}
		var marker ServerMarker
		if err := json.Unmarshal(data, &marker); err != nil {
			session.Close()
			return nil, fmt.Errorf("parse %s marker: %w", source, err)
		}
		marker.Export.MountPoint = export.MountPoint
		session.Markers[export.Target] = marker
		storage := par3bench.DescribeStorage(par3bench.Target{Name: export.Target, Work: export.MountPoint})
		fmt.Fprintf(log, "nfs client: %s -> %s\n", export.Target, storage.StorageLabel())
	}
	if err := os.MkdirAll(LocalWork, 0o755); err != nil {
		session.Close()
		return nil, err
	}
	if session.Link != nil {
		if err := checkLink(ctx, MountAsync, session.Link, log); err != nil {
			session.Close()
			return nil, err
		}
	}
	session.LocalFS = backingFS(LocalWork)
	if config.Ext4 != "" {
		session.Ext4 = true
		loop, err := mountExt4(ctx, config.Ext4, log)
		session.loop = loop
		if err != nil {
			session.Close()
			return nil, err
		}
		session.mounted = append(session.mounted, LocalExt4)
	}
	return session, nil
}

// mountExt4 makes a fresh sparse ext4 image of size and mounts it at
// LocalExt4 through a loop device, which it returns once attached, even when
// the mount then fails. A container's /dev holds only the loop nodes that
// existed when it started, so the node for the device the kernel hands out
// is made here when it is missing.
func mountExt4(ctx context.Context, size string, log io.Writer) (string, error) {
	if err := os.MkdirAll(filepath.Dir(Ext4Image), 0o755); err != nil {
		return "", err
	}
	if err := os.Remove(Ext4Image); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(LocalExt4, 0o755); err != nil {
		return "", err
	}
	run := func(args ...string) (string, error) {
		fmt.Fprintf(log, "nfs client: %s\n", strings.Join(args, " "))
		output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return strings.TrimSpace(string(output)), nil
	}
	if _, err := run("truncate", "-s", size, Ext4Image); err != nil {
		return "", err
	}
	if _, err := run("mkfs.ext4", "-q", "-F", "-E", "nodiscard", Ext4Image); err != nil {
		return "", err
	}
	device, err := run("losetup", "-f")
	if err != nil {
		return "", err
	}
	minor, ok := strings.CutPrefix(device, "/dev/loop")
	if !ok || minor == "" || strings.Trim(minor, "0123456789") != "" {
		return "", fmt.Errorf("losetup -f: unexpected device %q", device)
	}
	if _, err := os.Stat(device); os.IsNotExist(err) {
		if _, err := run("mknod", device, "b", "7", minor); err != nil {
			return "", err
		}
	}
	if _, err := run("losetup", device, Ext4Image); err != nil {
		return "", err
	}
	if _, err := run("mount", device, LocalExt4); err != nil {
		return device, err
	}
	return device, nil
}

// TargetArgs are this session's `par3 run` target arguments.
func (s *Session) TargetArgs() []string {
	args := TargetArgs(s.Markers, s.Config.Mount, s.LocalFS)
	if s.Link != nil {
		args = withLinkMeta(args, *s.Link)
	}
	if s.Ext4 {
		args = append(args, Ext4TargetArgs()...)
	}
	return args
}

// withLinkMeta records a throttled link on every NFS target's metadata.
func withLinkMeta(args []string, link LinkCheck) []string {
	meta := fmt.Sprintf(",rate_mbps=%d,link_read_mbps=%.1f,link_write_mbps=%.1f", link.RateMBps, link.ReadMBps, link.WriteMBps)
	out := append([]string(nil), args...)
	for i := 1; i < len(out); i++ {
		if out[i-1] == "--target-meta" && strings.HasPrefix(out[i], "nfs-") {
			out[i] += meta
		}
	}
	return out
}

// Ext4TargetArgs name the loop-mounted ext4 target.
func Ext4TargetArgs() []string {
	return []string{"--target", "local-ext4=" + LocalExt4,
		"--target-meta", "local-ext4:storage=loop-image,backing_fs=ext4"}
}

// Close unmounts the exports and puts LOCALIO back as it was.
func (s *Session) Close() {
	for i := len(s.mounted) - 1; i >= 0; i-- {
		if output, err := exec.Command("umount", s.mounted[i]).CombinedOutput(); err != nil {
			fmt.Fprintf(s.log, "nfs client: umount %s: %v %s\n", s.mounted[i], err, strings.TrimSpace(string(output)))
		}
	}
	s.mounted = nil
	if s.loop != "" {
		if output, err := exec.Command("losetup", "-d", s.loop).CombinedOutput(); err != nil {
			fmt.Fprintf(s.log, "nfs client: losetup -d %s: %v %s\n", s.loop, err, strings.TrimSpace(string(output)))
		}
		s.loop = ""
	}
	if s.Ext4 {
		_ = os.Remove(Ext4Image)
		s.Ext4 = false
	}
	if s.shaped != "" {
		unshape(s.shaped, s.log)
		s.shaped = ""
	}
	if s.localIOSaved != "" {
		if err := os.WriteFile(localIOParameter, []byte(s.localIOSaved), 0o644); err != nil {
			fmt.Fprintf(s.log, "nfs client: restore localio=%s: %v\n", s.localIOSaved, err)
		}
		s.localIOSaved = ""
	}
}

// BuildCommands are the cargo invocations that build the candidate and
// engine_perf from the read-only source tree into the cache volume. Symbols
// stay in, as on the fleet, so a profile on the client can be attributed.
func BuildCommands() [][]string {
	return [][]string{
		{"cargo", "build", "--locked", "--release", "-p", "rarpar", "--bin", "rarpar"},
		{"cargo", "build", "--locked", "--release", "-p", "par3-rs", "--example", "engine_perf"},
	}
}

// BuildEnv is the environment BuildCommands run with.
func BuildEnv() []string {
	return []string{
		"CARGO_HOME=" + filepath.Join(Cache, "cargo"),
		"CARGO_TARGET_DIR=" + filepath.Join(Cache, "target"),
		"CARGO_PROFILE_RELEASE_STRIP=none",
	}
}

// Build runs BuildCommands in the source tree.
func Build(ctx context.Context, log io.Writer) error {
	for _, args := range append([][]string{{"rustc", "--version"}, {"cargo", "--version"}}, BuildCommands()...) {
		fmt.Fprintf(log, "nfs client: %s\n", strings.Join(args, " "))
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = Source
		cmd.Env = append(os.Environ(), BuildEnv()...)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}
