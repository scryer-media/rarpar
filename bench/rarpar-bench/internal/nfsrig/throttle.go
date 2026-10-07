package nfsrig

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

// ifbDevice receives the client's inbound traffic so it can be shaped: a
// qdisc shapes only what a device sends, and the reads arrive inbound.
const ifbDevice = "ifb-rig"

// probeName is the link check's file on the async export.
const probeName = ".rig-link-probe"

// probeBytes is the link check's file size.
const probeBytes = 1 << 30

// ShapeCommands throttle the client's network interface iface to rateMBps
// megabytes a second each way, inside the client's own network namespace so
// the server is unchanged: a token bucket on what the client sends, and the
// same bucket on an IFB device its inbound traffic is redirected through.
func ShapeCommands(iface string, rateMBps int) [][]string {
	rate := strconv.Itoa(rateMBps*8) + "mbit"
	tbf := func(dev string) []string {
		return []string{"tc", "qdisc", "replace", "dev", dev, "root", "tbf", "rate", rate, "burst", "1mbit", "latency", "50ms"}
	}
	return [][]string{
		{"ip", "link", "add", ifbDevice, "type", "ifb"},
		{"ip", "link", "set", ifbDevice, "up"},
		tbf(iface),
		{"tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"},
		{"tc", "filter", "add", "dev", iface, "parent", "ffff:", "matchall", "action", "mirred", "egress", "redirect", "dev", ifbDevice},
		tbf(ifbDevice),
	}
}

// routeInterface is the device of the client's default route.
func routeInterface(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "ip", "-o", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("ip route show default: %w", err)
	}
	fields := strings.Fields(string(output))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no default route device in %q", strings.TrimSpace(string(output)))
}

// shape applies ShapeCommands to the default route's device and returns it.
func shape(ctx context.Context, rateMBps int, log io.Writer) (string, error) {
	iface, err := routeInterface(ctx)
	if err != nil {
		return "", err
	}
	for _, args := range ShapeCommands(iface, rateMBps) {
		fmt.Fprintf(log, "nfs client: %s\n", strings.Join(args, " "))
		if output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput(); err != nil {
			return iface, fmt.Errorf("%s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return iface, nil
}

// unshape removes what shape added. The namespace goes with the container
// anyway; this keeps a reused one clean.
func unshape(iface string, log io.Writer) {
	for _, args := range [][]string{
		{"tc", "qdisc", "del", "dev", iface, "root"},
		{"tc", "qdisc", "del", "dev", iface, "handle", "ffff:", "ingress"},
		{"ip", "link", "del", ifbDevice},
	} {
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			fmt.Fprintf(log, "nfs client: %s: %v %s\n", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
}

// LinkCheck is the measured throughput of a throttled link: a 1 GiB file
// written to the async export with direct I/O (buffered, its dirty pages
// would pile up behind the slow link and overrun a low-memory client), then
// read back with plain dd after the page cache was dropped, so every byte
// crosses the link.
type LinkCheck struct {
	Interface string  `json:"interface"`
	RateMBps  int     `json:"rate_mbps"`
	Bytes     int64   `json:"bytes"`
	WriteMBps float64 `json:"write_mbps"`
	ReadMBps  float64 `json:"read_mbps"`
}

// checkLink measures the link through the export mounted at dir.
func checkLink(ctx context.Context, dir string, check *LinkCheck, log io.Writer) error {
	path := filepath.Join(dir, probeName)
	defer os.Remove(path)
	dd := func(args ...string) (float64, error) {
		fmt.Fprintf(log, "nfs client: dd %s\n", strings.Join(args, " "))
		started := time.Now()
		output, err := exec.CommandContext(ctx, "dd", args...).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("dd %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return float64(probeBytes) / 1e6 / time.Since(started).Seconds(), nil
	}
	var err error
	count := strconv.Itoa(probeBytes >> 20)
	if check.WriteMBps, err = dd("if=/dev/zero", "of="+path, "bs=1M", "count="+count, "oflag=direct", "conv=fsync", "status=none"); err != nil {
		return err
	}
	if err := par3bench.DropCaches(); err != nil {
		return fmt.Errorf("drop caches before the link read: %w", err)
	}
	if check.ReadMBps, err = dd("if="+path, "of=/dev/null", "bs=1M", "status=none"); err != nil {
		return err
	}
	check.Bytes = probeBytes
	fmt.Fprintf(log, "nfs client: link %s at %d MB/s: write %.1f MB/s, cold read %.1f MB/s\n",
		check.Interface, check.RateMBps, check.WriteMBps, check.ReadMBps)
	return nil
}
