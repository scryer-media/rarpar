package nfsrig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Project is the compose project name the host role uses.
const Project = "rarpar-nfs"

// Clients are the compose services that can run the suite: the default
// client, and one whose memory cgroup is smaller than the largest set file so
// the page cache cannot keep a whole file between two read passes.
var Clients = []string{"bench-client", "bench-client-lowmem"}

// HostOptions drive `nfs run` and `nfs down` on the host.
type HostOptions struct {
	Docker  string
	Context string
	Compose string
	// Source is the repository root bind-mounted read-only into the client.
	Source string
	// Results is the host evidence directory, mounted at /results.
	Results string
	// Label names this run's subdirectory of Results.
	Label   string
	Service string
	// Env is extra client environment (mount options, RIG_BUILD, ...).
	Env []string
	// SuiteArgs are passed through to `par3 run` inside the client.
	SuiteArgs []string
	// LoadEvery is the host load sampling interval.
	LoadEvery time.Duration
	Log       io.Writer
}

func (o HostOptions) compose(args ...string) []string {
	command := []string{}
	if o.Context != "" {
		command = append(command, "--context", o.Context)
	}
	return append(append(command, "compose", "-p", Project, "-f", o.Compose), args...)
}

// UpArgs starts the server and waits for its health check.
func (o HostOptions) UpArgs() []string {
	return o.compose("up", "-d", "--build", "--wait", "nfs-server")
}

// RunArgs runs the suite in a one-off client container.
func (o HostOptions) RunArgs() []string {
	args := []string{"run", "--rm", "--build"}
	env := append([]string(nil), o.Env...)
	sort.Strings(env)
	for _, entry := range env {
		args = append(args, "-e", entry)
	}
	args = append(args, o.Service, "nfs", "client", "--", "--out", Results+"/"+o.Label)
	return o.compose(append(args, o.SuiteArgs...)...)
}

// DownArgs stops the project. Volumes are kept unless asked: the cache volume
// holds the builds and the datasets are slow to regenerate.
func (o HostOptions) DownArgs(volumes bool) []string {
	args := []string{"down"}
	if volumes {
		args = append(args, "--volumes")
	}
	return o.compose(args...)
}

// ComposeEnv is the environment compose interpolates the file with.
func (o HostOptions) ComposeEnv() []string {
	return []string{"RIG_SOURCE=" + o.Source, "RIG_RESULTS=" + o.Results}
}

// Validate checks the options before anything starts.
func (o *HostOptions) Validate() error {
	if o.Docker == "" {
		o.Docker = "docker"
	}
	if o.Service == "" {
		o.Service = Clients[0]
	}
	known := false
	for _, client := range Clients {
		known = known || client == o.Service
	}
	if !known {
		return fmt.Errorf("unknown client service %q (want %s)", o.Service, strings.Join(Clients, " or "))
	}
	// The label is one path component on the host results directory and on
	// the container's /results mount, so it must name a directory inside both.
	if o.Label == "" || o.Label == "." || o.Label == ".." || strings.ContainsAny(o.Label, "/\\ ") || !filepath.IsLocal(o.Label) {
		return fmt.Errorf("--label %q must be a plain directory name (not . or .., no separators or spaces)", o.Label)
	}
	for _, path := range []*string{&o.Compose, &o.Source, &o.Results} {
		if *path == "" {
			return fmt.Errorf("--compose, --source and --results are required")
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	for _, entry := range o.Env {
		if !strings.Contains(entry, "=") {
			return fmt.Errorf("--env %q: want VAR=value", entry)
		}
	}
	if o.LoadEvery <= 0 {
		o.LoadEvery = time.Minute
	}
	return nil
}

// LoadSample is one host load-average reading.
type LoadSample struct {
	UTC  string  `json:"utc"`
	Load float64 `json:"load1"`
}

// HostRun starts the server, runs the suite in a client and samples the
// host's load average beside it into <results>/<label>/host-load.jsonl. The
// containers share the host's cores with whatever else it runs, so the load
// belongs beside every table the run produces.
func HostRun(ctx context.Context, options HostOptions, loadAverage func() float64) error {
	if err := options.Validate(); err != nil {
		return err
	}
	out := filepath.Join(options.Results, options.Label)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := options.docker(ctx, options.UpArgs()); err != nil {
		return err
	}
	file, err := os.Create(filepath.Join(out, "host-load.jsonl"))
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	sample := func() {
		_ = encoder.Encode(LoadSample{UTC: time.Now().UTC().Format(time.RFC3339), Load: loadAverage()})
	}
	sample()
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(options.LoadEvery)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				sample()
			}
		}
	}()
	runErr := options.docker(ctx, options.RunArgs())
	close(done)
	<-stopped
	sample()
	return runErr
}

// HostDown stops the project.
func HostDown(ctx context.Context, options HostOptions, volumes bool) error {
	if options.Docker == "" {
		options.Docker = "docker"
	}
	// down mounts nothing, but compose still interpolates the client's
	// required bind sources; any path satisfies it.
	for _, path := range []*string{&options.Source, &options.Results} {
		if *path == "" {
			*path = os.TempDir()
		}
	}
	return options.docker(ctx, options.DownArgs(volumes))
}

func (o HostOptions) docker(ctx context.Context, args []string) error {
	if o.Log != nil {
		fmt.Fprintf(o.Log, "nfs: %s %s\n", o.Docker, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, o.Docker, args...)
	cmd.Env = append(os.Environ(), o.ComposeEnv()...)
	cmd.Stdout, cmd.Stderr = o.Log, o.Log
	if o.Log == nil {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", o.Docker, strings.Join(args[:min(len(args), 8)], " "), err)
	}
	return nil
}
