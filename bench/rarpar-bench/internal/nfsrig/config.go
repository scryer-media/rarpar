// Package nfsrig is the network-mount bench role: a compose project with a
// kernel NFS server and a Linux bench client that mounts its exports and runs
// the PAR3 suite with work directories on the mounts and on local disk, so
// remote and local rows come from one interleaved run.
//
// The pieces run in three places. `nfs server` is the server container's
// entrypoint (kernel nfsd, configured from the environment). `nfs client` runs
// in the client container: it mounts the exports, builds the binaries from the
// read-only source tree, and runs `par3 run` with one target per mount.
// `nfs run` runs on the host and drives docker compose. Everything that can be
// decided without Docker (mount options, the exports file, the targets) is a
// pure function here so it can be tested without Docker.
package nfsrig

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Fixed paths shared by the compose file and the roles.
const (
	ExportAsync = "/export/async"
	ExportSync  = "/export/sync"
	// Client mount points and the local work directory are kept short: the
	// reference's absolute volume paths have a length budget.
	MountAsync = "/na"
	MountSync  = "/ns"
	LocalWork  = "/w"
	// Cache holds the cargo home, the target directory and the reference
	// build across runs; Source is the read-only repository; Results is the
	// host's evidence directory.
	Cache   = "/cache"
	Source  = "/src"
	Results = "/results"
	// MarkerName is the file the server writes into every export root, so the
	// client can record what served its bytes.
	MarkerName = ".rarpar-nfs-server.json"
	// ReadyFile marks a server whose nfsd is up and exporting.
	ReadyFile = "/run/rarpar-nfs-ready"
)

// Export is one directory the server exports.
type Export struct {
	// Target is the bench target name of the mount ("nfs-async").
	Target string `json:"target"`
	Path   string `json:"path"`
	// Mode is the export's write semantics: "sync" commits every write before
	// replying; "async" replies first (fast, unsafe across a server crash).
	Mode       string `json:"mode"`
	FSID       int    `json:"fsid"`
	MountPoint string `json:"mount_point"`
}

// Exports is the fixed pair the rig serves: the same server, one export of
// each write mode, on separate volumes.
func Exports() []Export {
	return []Export{
		{Target: "nfs-async", Path: ExportAsync, Mode: "async", FSID: 11, MountPoint: MountAsync},
		{Target: "nfs-sync", Path: ExportSync, Mode: "sync", FSID: 12, MountPoint: MountSync},
	}
}

// ExportRoot is the NFSv4 pseudo-root: NFSv4 clients name exports relative
// to it, NFSv3 clients by their full path.
const ExportRoot = "/export"

// ExportsFile renders /etc/exports: the read-only v4 root, then the exports.
func ExportsFile(exports []Export) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s *(ro,fsid=0,crossmnt,no_subtree_check,no_root_squash,insecure)\n", ExportRoot)
	for _, export := range exports {
		fmt.Fprintf(&b, "%s *(rw,%s,no_subtree_check,no_root_squash,insecure,fsid=%d)\n", export.Path, export.Mode, export.FSID)
	}
	return b.String()
}

// Source is the mount source for an export at the given protocol version.
func (e Export) Source(server, version string) string {
	if version == "3" {
		return server + ":" + e.Path
	}
	return server + ":" + strings.TrimPrefix(e.Path, ExportRoot)
}

// ServerConfig is the server role's environment.
type ServerConfig struct {
	// Threads is the nfsd thread count (NFS_THREADS, default 8).
	Threads int `json:"threads"`
	// Versions lists the protocol versions served (NFS_SERVER_VERSIONS,
	// default "3,4.1,4.2"); v3 needs rpcbind and mountd, which run anyway.
	Versions []string `json:"versions"`
}

// ServerConfigFromEnv reads the server role's environment.
func ServerConfigFromEnv(getenv func(string) string) (ServerConfig, error) {
	config := ServerConfig{Threads: 8, Versions: []string{"3", "4.1", "4.2"}}
	if text := getenv("NFS_THREADS"); text != "" {
		threads, err := strconv.Atoi(text)
		if err != nil || threads < 1 {
			return ServerConfig{}, fmt.Errorf("NFS_THREADS=%q: want a positive integer", text)
		}
		config.Threads = threads
	}
	if text := getenv("NFS_SERVER_VERSIONS"); text != "" {
		config.Versions = nil
		for _, version := range strings.Split(text, ",") {
			version = strings.TrimSpace(version)
			switch version {
			case "3", "4", "4.0", "4.1", "4.2":
				config.Versions = append(config.Versions, version)
			case "":
			default:
				return ServerConfig{}, fmt.Errorf("NFS_SERVER_VERSIONS: unknown version %q", version)
			}
		}
		if len(config.Versions) == 0 {
			return ServerConfig{}, fmt.Errorf("NFS_SERVER_VERSIONS=%q lists no version", text)
		}
	}
	return config, nil
}

// NFSDArgs is rpc.nfsd's command line: every known version off unless
// served, then the thread count.
func (config ServerConfig) NFSDArgs() []string {
	served := map[string]bool{}
	for _, version := range config.Versions {
		if version == "4" {
			version = "4.0"
		}
		served[version] = true
	}
	var args []string
	for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
		flag := "-N"
		if served[version] {
			flag = "-V"
		}
		args = append(args, flag, version)
	}
	return append(args, strconv.Itoa(config.Threads))
}

// MountConfig is the client's NFS mount options, one environment variable
// each so compose can expose them.
type MountConfig struct {
	Version string `json:"vers"`
	Proto   string `json:"proto"`
	RSize   int    `json:"rsize,omitempty"`
	WSize   int    `json:"wsize,omitempty"`
	// Hard is "hard" or "soft".
	Hard string `json:"hard"`
	// ACTimeo is the attribute cache lifetime in seconds ("" keeps the
	// kernel's acregmin/acregmax defaults, "0" is noac-like).
	ACTimeo string `json:"actimeo,omitempty"`
	// Sync adds the client-side "sync" mount option: every write is sent and
	// committed before write(2) returns, independent of the export's mode.
	Sync     bool   `json:"sync"`
	NConnect int    `json:"nconnect,omitempty"`
	Extra    string `json:"extra,omitempty"`
	// LocalIO keeps the kernel's NFS LOCALIO bypass enabled. It is off by
	// default: with client and server on one kernel, LOCALIO short-circuits
	// the protocol and the "remote" rows would measure local disk.
	LocalIO bool `json:"localio"`
}

// MountConfigFromEnv reads the client's mount environment.
func MountConfigFromEnv(getenv func(string) string) (MountConfig, error) {
	config := MountConfig{Version: "4.1", Proto: "tcp", RSize: 1 << 20, WSize: 1 << 20, Hard: "hard"}
	if text := getenv("NFS_VERS"); text != "" {
		config.Version = text
	}
	switch config.Version {
	case "3", "4", "4.0", "4.1", "4.2":
	default:
		return MountConfig{}, fmt.Errorf("NFS_VERS=%q: want 3, 4.0, 4.1 or 4.2", config.Version)
	}
	if text := getenv("NFS_PROTO"); text != "" {
		config.Proto = text
	}
	for _, size := range []struct {
		name  string
		value *int
	}{{"NFS_RSIZE", &config.RSize}, {"NFS_WSIZE", &config.WSize}} {
		text := getenv(size.name)
		if text == "" {
			continue
		}
		value, err := strconv.Atoi(text)
		if err != nil || value < 0 {
			return MountConfig{}, fmt.Errorf("%s=%q: want a byte count (0 = negotiate)", size.name, text)
		}
		*size.value = value
	}
	if text := getenv("NFS_HARD"); text != "" {
		if text != "hard" && text != "soft" {
			return MountConfig{}, fmt.Errorf("NFS_HARD=%q: want hard or soft", text)
		}
		config.Hard = text
	}
	if text := getenv("NFS_ACTIMEO"); text != "" {
		if _, err := strconv.Atoi(text); err != nil {
			return MountConfig{}, fmt.Errorf("NFS_ACTIMEO=%q: want seconds", text)
		}
		config.ACTimeo = text
	}
	switch text := getenv("NFS_CLIENT_SYNC"); text {
	case "", "0", "async":
	case "1", "sync":
		config.Sync = true
	default:
		return MountConfig{}, fmt.Errorf("NFS_CLIENT_SYNC=%q: want sync or async", text)
	}
	if text := getenv("NFS_NCONNECT"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 1 || value > 16 {
			return MountConfig{}, fmt.Errorf("NFS_NCONNECT=%q: want 1-16", text)
		}
		config.NConnect = value
	}
	config.Extra = strings.Trim(getenv("NFS_EXTRA_OPTS"), ", ")
	switch text := getenv("NFS_LOCALIO"); text {
	case "", "off", "0":
	case "on", "1":
		config.LocalIO = true
	default:
		return MountConfig{}, fmt.Errorf("NFS_LOCALIO=%q: want on or off", text)
	}
	return config, nil
}

// Options renders the -o string for mount(8).
func (config MountConfig) Options() string {
	options := []string{"vers=" + config.Version, "proto=" + config.Proto, config.Hard}
	if config.RSize > 0 {
		options = append(options, "rsize="+strconv.Itoa(config.RSize))
	}
	if config.WSize > 0 {
		options = append(options, "wsize="+strconv.Itoa(config.WSize))
	}
	if config.ACTimeo != "" {
		options = append(options, "actimeo="+config.ACTimeo)
	}
	if config.Sync {
		options = append(options, "sync")
	}
	if config.NConnect > 0 {
		options = append(options, "nconnect="+strconv.Itoa(config.NConnect))
	}
	if config.Version == "3" {
		// No lock manager runs in the rig, and nothing it measures locks.
		options = append(options, "nolock")
	}
	if config.Extra != "" {
		options = append(options, config.Extra)
	}
	return strings.Join(options, ",")
}

// ServerMarker is what the server writes into each export root.
type ServerMarker struct {
	// Kind is the server implementation: "kernel-nfsd".
	Kind          string       `json:"kind"`
	Kernel        string       `json:"kernel"`
	Export        Export       `json:"export"`
	ExportOptions string       `json:"export_options"`
	Config        ServerConfig `json:"config"`
	// BackingFS is the filesystem type under the export, from the server's
	// mount table.
	BackingFS string `json:"backing_fs,omitempty"`
}

// TargetArgs are the `par3 run` arguments naming the rig's targets: local
// disk first (it seeds the canonical set), then each export, with what the
// client cannot see about each recorded as target metadata.
func TargetArgs(markers map[string]ServerMarker, mount MountConfig, localFS string) []string {
	args := []string{"--target", "local=" + LocalWork,
		"--target-meta", "local:storage=container-volume,backing_fs=" + orUnknown(localFS)}
	names := make([]string, 0, len(markers))
	for name := range markers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		marker := markers[name]
		meta := []string{
			"server=" + marker.Kind,
			"export=" + marker.Export.Mode,
			"server_kernel=" + marker.Kernel,
			"server_threads=" + strconv.Itoa(marker.Config.Threads),
			"backing_fs=" + orUnknown(marker.BackingFS),
			"localio=" + onOff(mount.LocalIO),
			"requested=" + strings.ReplaceAll(mount.Options(), ",", ";"),
		}
		args = append(args, "--target", name+"="+marker.Export.MountPoint,
			"--target-meta", name+":"+strings.Join(meta, ","))
	}
	return args
}

func orUnknown(text string) string {
	if text == "" {
		return "unknown"
	}
	return text
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
