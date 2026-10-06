package par3bench

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Target is one storage location a run measures: a work directory holding the
// datasets, canonical carriers and stages for that storage. A run with several
// targets interleaves every row over every target, so local and remote numbers
// come from the same process, the same binaries and the same load.
type Target struct {
	// Name labels the target's rows ("local", "nfs-async"). Empty for the
	// single unnamed target of a run that did not ask for any.
	Name string `json:"name,omitempty"`
	Work string `json:"work"`
	// Meta is what the harness cannot see from the client side, supplied by
	// whoever set the storage up: the server type, the export's sync mode.
	Meta map[string]string `json:"meta,omitempty"`
}

// Storage describes where a target's bytes live. Every run record carries a
// copy, so a row read out of context still says what it measured.
type Storage struct {
	Target string `json:"target,omitempty"`
	Work   string `json:"work"`
	// Mount point, filesystem type, source and options of the mount holding
	// Work, from /proc/self/mountinfo (Linux only).
	MountPoint   string `json:"mount_point,omitempty"`
	FSType       string `json:"fs_type,omitempty"`
	Source       string `json:"source,omitempty"`
	MountOptions string `json:"mount_options,omitempty"`
	SuperOptions string `json:"super_options,omitempty"`
	// NFSOptions is the negotiated option line the NFS client reports in
	// /proc/self/mountstats ("opts:"): version, rsize/wsize, hard/soft,
	// timeo, attribute cache bounds, transport.
	NFSOptions string            `json:"nfs_options,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// IsNFS reports whether the storage is an NFS mount.
func (s Storage) IsNFS() bool { return strings.HasPrefix(s.FSType, "nfs") }

// MountInfo is one line of /proc/self/mountinfo.
type MountInfo struct {
	MountPoint   string
	Options      string
	FSType       string
	Source       string
	SuperOptions string
}

// ParseMountInfo reads /proc/self/mountinfo text.
func ParseMountInfo(text string) []MountInfo {
	var mounts []MountInfo
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(fields) < separator+3 {
			continue
		}
		mount := MountInfo{
			MountPoint: unescapeMount(fields[4]), Options: fields[5],
			FSType: fields[separator+1], Source: unescapeMount(fields[separator+2]),
		}
		if len(fields) > separator+3 {
			mount.SuperOptions = fields[separator+3]
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

// unescapeMount undoes the kernel's octal escapes (\040 for a space).
func unescapeMount(text string) string {
	if !strings.Contains(text, `\`) {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '\\' && i+4 <= len(text) {
			if value, err := strconv.ParseUint(text[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		b.WriteByte(text[i])
	}
	return b.String()
}

// MountFor is the mount holding path: the longest mount point that is path or
// one of its parents. The last such line wins, as the kernel stacks mounts.
func MountFor(mounts []MountInfo, path string) (MountInfo, bool) {
	var best MountInfo
	found := false
	for _, mount := range mounts {
		if !underMount(path, mount.MountPoint) {
			continue
		}
		if !found || len(mount.MountPoint) >= len(best.MountPoint) {
			best, found = mount, true
		}
	}
	return best, found
}

func underMount(path, mountPoint string) bool {
	if mountPoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mountPoint || strings.HasPrefix(path, mountPoint+"/")
}

// NFSOp is one NFS operation's cumulative counters from the mountstats
// per-op table.
type NFSOp struct {
	Ops       int64 `json:"ops"`
	Trans     int64 `json:"trans"`
	Timeouts  int64 `json:"timeouts,omitempty"`
	BytesSent int64 `json:"bytes_sent"`
	BytesRecv int64 `json:"bytes_recv"`
	// QueueMS, RTTMS and ExecuteMS are cumulative milliseconds.
	QueueMS   int64 `json:"queue_ms"`
	RTTMS     int64 `json:"rtt_ms"`
	ExecuteMS int64 `json:"execute_ms"`
}

// NFSStats is one NFS mount's client-side counters, or a delta of two.
type NFSStats struct {
	// Ops maps the operation name (READ, WRITE, COMMIT, GETATTR, ...) to its
	// counters. A delta keeps only the operations that moved.
	Ops map[string]NFSOp `json:"ops,omitempty"`
	// The "bytes:" line: application reads and writes through the page
	// cache (normal), O_DIRECT (direct), and what crossed the wire (server).
	NormalReadBytes  int64 `json:"normal_read_bytes"`
	NormalWriteBytes int64 `json:"normal_write_bytes"`
	ServerReadBytes  int64 `json:"server_read_bytes"`
	ServerWriteBytes int64 `json:"server_write_bytes"`
	// Options is the mount's "opts:" line.
	Options string `json:"options,omitempty"`
}

// TotalOps sums every operation's count.
func (s NFSStats) TotalOps() int64 {
	var total int64
	for _, op := range s.Ops {
		total += op.Ops
	}
	return total
}

// Op returns one operation's count (zero when absent).
func (s NFSStats) Op(name string) int64 { return s.Ops[name].Ops }

// MetadataOps counts the operations that move no file data: everything but
// READ, WRITE and COMMIT.
func (s NFSStats) MetadataOps() int64 {
	return s.TotalOps() - s.Op("READ") - s.Op("WRITE") - s.Op("COMMIT")
}

// Sub is s - before, keeping only operations whose count changed.
func (s NFSStats) Sub(before NFSStats) NFSStats {
	delta := NFSStats{
		Ops:              map[string]NFSOp{},
		NormalReadBytes:  s.NormalReadBytes - before.NormalReadBytes,
		NormalWriteBytes: s.NormalWriteBytes - before.NormalWriteBytes,
		ServerReadBytes:  s.ServerReadBytes - before.ServerReadBytes,
		ServerWriteBytes: s.ServerWriteBytes - before.ServerWriteBytes,
	}
	for name, after := range s.Ops {
		was := before.Ops[name]
		op := NFSOp{
			Ops: after.Ops - was.Ops, Trans: after.Trans - was.Trans, Timeouts: after.Timeouts - was.Timeouts,
			BytesSent: after.BytesSent - was.BytesSent, BytesRecv: after.BytesRecv - was.BytesRecv,
			QueueMS: after.QueueMS - was.QueueMS, RTTMS: after.RTTMS - was.RTTMS, ExecuteMS: after.ExecuteMS - was.ExecuteMS,
		}
		if op.Ops != 0 {
			delta.Ops[name] = op
		}
	}
	return delta
}

// ParseMountStats reads /proc/self/mountstats text and returns the NFS
// counters of the mount at mountPoint.
func ParseMountStats(text, mountPoint string) (NFSStats, bool) {
	var stats NFSStats
	found, inMount, inOps := false, false, false
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "device ") {
			if found {
				break
			}
			inMount, inOps = false, false
			// device SOURCE mounted on POINT with fstype TYPE ...
			if _, rest, ok := strings.Cut(line, " mounted on "); ok {
				if point, _, ok := strings.Cut(rest, " with fstype "); ok && unescapeMount(point) == mountPoint {
					inMount, found = true, true
					stats.Ops = map[string]NFSOp{}
				}
			}
			continue
		}
		if !inMount {
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "opts:"):
			stats.Options = strings.TrimSpace(strings.TrimPrefix(trimmed, "opts:"))
		case strings.HasPrefix(trimmed, "bytes:"):
			values := int64Fields(strings.TrimPrefix(trimmed, "bytes:"))
			if len(values) >= 6 {
				stats.NormalReadBytes, stats.NormalWriteBytes = values[0], values[1]
				stats.ServerReadBytes, stats.ServerWriteBytes = values[4], values[5]
			}
		case trimmed == "per-op statistics":
			inOps = true
		case inOps:
			name, rest, ok := strings.Cut(trimmed, ":")
			if !ok || name == "" || strings.ContainsAny(name, " \t") {
				continue
			}
			values := int64Fields(rest)
			if len(values) < 8 {
				continue
			}
			stats.Ops[name] = NFSOp{
				Ops: values[0], Trans: values[1], Timeouts: values[2], BytesSent: values[3], BytesRecv: values[4],
				QueueMS: values[5], RTTMS: values[6], ExecuteMS: values[7],
			}
		}
	}
	return stats, found
}

func int64Fields(text string) []int64 {
	var values []int64
	for _, field := range strings.Fields(text) {
		value, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return values
		}
		values = append(values, value)
	}
	return values
}

// ParseTarget reads "NAME=PATH".
func ParseTarget(text string) (Target, error) {
	name, path, ok := strings.Cut(text, "=")
	if !ok || name == "" || path == "" {
		return Target{}, fmt.Errorf("target %q: want NAME=PATH", text)
	}
	if strings.ContainsAny(name, " /\\@") {
		return Target{}, fmt.Errorf("target name %q may not contain spaces, slashes or @", name)
	}
	return Target{Name: name, Work: path}, nil
}

// ApplyTargetMeta applies one "NAME:key=value[,key=value]" to the named target.
func ApplyTargetMeta(targets []Target, text string) error {
	name, assignments, ok := strings.Cut(text, ":")
	if !ok || name == "" || assignments == "" {
		return fmt.Errorf("target meta %q: want NAME:key=value[,key=value]", text)
	}
	for i := range targets {
		if targets[i].Name != name {
			continue
		}
		if targets[i].Meta == nil {
			targets[i].Meta = map[string]string{}
		}
		for _, assignment := range strings.Split(assignments, ",") {
			key, value, ok := strings.Cut(assignment, "=")
			if !ok || key == "" {
				return fmt.Errorf("target meta %q: %q is not key=value", text, assignment)
			}
			targets[i].Meta[key] = value
		}
		return nil
	}
	return fmt.Errorf("target meta %q names no --target", text)
}

// DescribeStorage resolves what the harness can see of a target's storage.
// Off Linux it records only the path and the supplied metadata.
func DescribeStorage(target Target) Storage {
	storage := Storage{Target: target.Name, Work: target.Work, Meta: target.Meta}
	path := target.Work
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return storage
	}
	mount, ok := MountFor(ParseMountInfo(string(data)), path)
	if !ok {
		return storage
	}
	storage.MountPoint, storage.FSType, storage.Source = mount.MountPoint, mount.FSType, mount.Source
	storage.MountOptions, storage.SuperOptions = mount.Options, mount.SuperOptions
	if storage.IsNFS() {
		if stats, ok := readNFSStats(storage.MountPoint); ok {
			storage.NFSOptions = stats.Options
		}
	}
	return storage
}

func readNFSStats(mountPoint string) (NFSStats, bool) {
	data, err := os.ReadFile("/proc/self/mountstats")
	if err != nil {
		return NFSStats{}, false
	}
	return ParseMountStats(string(data), mountPoint)
}

// StorageLabel is a one-line summary for logs and reports.
func (s Storage) StorageLabel() string {
	parts := []string{}
	if s.FSType != "" {
		parts = append(parts, s.FSType)
	}
	keys := make([]string, 0, len(s.Meta))
	for key := range s.Meta {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+s.Meta[key])
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

// parseLoadAverage reads the first number of a load average line.
func parseLoadAverage(text string) float64 {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return value
}
