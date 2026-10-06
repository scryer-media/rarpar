package nfsrig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	return config, nil
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
	LocalFS      string
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
	session.LocalFS = backingFS(LocalWork)
	return session, nil
}

// TargetArgs are this session's `par3 run` target arguments.
func (s *Session) TargetArgs() []string {
	return TargetArgs(s.Markers, s.Config.Mount, s.LocalFS)
}

// Close unmounts the exports and puts LOCALIO back as it was.
func (s *Session) Close() {
	for i := len(s.mounted) - 1; i >= 0; i-- {
		if output, err := exec.Command("umount", s.mounted[i]).CombinedOutput(); err != nil {
			fmt.Fprintf(s.log, "nfs client: umount %s: %v %s\n", s.mounted[i], err, strings.TrimSpace(string(output)))
		}
	}
	s.mounted = nil
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
