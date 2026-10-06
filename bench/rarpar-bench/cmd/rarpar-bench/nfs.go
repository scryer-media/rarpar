package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/nfsrig"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

const nfsUsage = `Usage:
  rarpar-bench nfs run --label NAME [--results DIR] [--source DIR] [--compose PATH] [--context NAME]
        [--service bench-client|bench-client-lowmem] [--env VAR=V]... [--load-every 1m] -- [par3 run args]
  rarpar-bench nfs down [--context NAME] [--compose PATH] [--volumes]
  rarpar-bench nfs server          (server container entrypoint)
  rarpar-bench nfs ready           (server health check)
  rarpar-bench nfs client -- [par3 run args]   (client container)

The network-mount rig: a compose project (bench/nfs) with a kernel nfsd
server exporting one async and one sync export, and a Linux client that
mounts both and runs the PAR3 suite with three targets, local (the client's
volume disk), nfs-async and nfs-sync, interleaved in one run. Mount options
are client environment variables (NFS_VERS, NFS_PROTO, NFS_RSIZE, NFS_WSIZE,
NFS_HARD, NFS_ACTIMEO, NFS_CLIENT_SYNC, NFS_NCONNECT, NFS_EXTRA_OPTS,
NFS_LOCALIO). See docs/benchmarking.md.
`

func runNFS(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, nfsUsage)
		return fmt.Errorf("nfs requires run, down, server, ready, or client")
	}
	switch args[0] {
	case "run":
		return runNFSHost(ctx, args[1:])
	case "down":
		return runNFSDown(ctx, args[1:])
	case "server":
		config, err := nfsrig.ServerConfigFromEnv(os.Getenv)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return nfsrig.Server(ctx, config, os.Stderr)
	case "ready":
		return nfsrig.Ready()
	case "client":
		return runNFSClient(ctx, args[1:], stdout)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, nfsUsage)
		return nil
	default:
		return fmt.Errorf("unknown nfs command %q", args[0])
	}
}

// splitPassthrough separates a role's own flags from the arguments after
// "--", which go to `par3 run` unchanged.
func splitPassthrough(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func nfsHostFlags(name string) (*flag.FlagSet, *nfsrig.HostOptions) {
	options := &nfsrig.HostOptions{}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.StringVar(&options.Docker, "docker", "docker", "Docker executable")
	flags.StringVar(&options.Context, "context", os.Getenv("RARPAR_NFS_DOCKER_CONTEXT"), "Docker context (default: the CLI's current context)")
	flags.StringVar(&options.Compose, "compose", defaultPath("../nfs/compose.yaml"), "compose file")
	return flags, options
}

func runNFSHost(ctx context.Context, args []string) error {
	own, suite := splitPassthrough(args)
	flags, options := nfsHostFlags("nfs run")
	flags.StringVar(&options.Source, "source", defaultPath("../.."), "repository root, mounted read-only in the client")
	flags.StringVar(&options.Results, "results", defaultPath("../../target/bench/nfs"), "host evidence directory")
	flags.StringVar(&options.Label, "label", "", "run label: the results subdirectory")
	flags.StringVar(&options.Service, "service", nfsrig.Clients[0], "client service")
	flags.DurationVar(&options.LoadEvery, "load-every", time.Minute, "host load-average sampling interval")
	var env stringList
	flags.Var(&env, "env", "client environment VAR=value (repeatable)")
	if err := flags.Parse(own); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q (suite arguments go after --)", flags.Arg(0))
	}
	options.Compose, options.Source, options.Results = workspacePath(options.Compose), workspacePath(options.Source), workspacePath(options.Results)
	options.Env, options.SuiteArgs, options.Log = env, suite, os.Stderr
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return nfsrig.HostRun(ctx, *options, par3bench.LoadAverage)
}

func runNFSDown(ctx context.Context, args []string) error {
	flags, options := nfsHostFlags("nfs down")
	volumes := flags.Bool("volumes", false, "also remove the exports, local work and cache volumes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	options.Compose, options.Log = workspacePath(options.Compose), os.Stderr
	return nfsrig.HostDown(ctx, *options, *volumes)
}

// runNFSClient mounts the exports, builds what is missing, and runs the PAR3
// suite with one target per mount plus the local control.
func runNFSClient(ctx context.Context, args []string, stdout io.Writer) error {
	own, suite := splitPassthrough(args)
	if len(own) != 0 {
		return fmt.Errorf("nfs client takes its settings from the environment; suite arguments go after --")
	}
	config, err := nfsrig.ClientConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	binaries := nfsrig.DefaultBinaries()
	if config.Build {
		if err := nfsrig.Build(ctx, os.Stderr); err != nil {
			return err
		}
	}
	if _, err := os.Stat(binaries.Reference); err != nil && config.Reference {
		lock, err := bench.LoadToolchains(filepath.Join(nfsrig.Source, "bench", "rarpar-bench", "config", "toolchains.json"))
		if err != nil {
			return err
		}
		build, err := par3bench.BuildReference(ctx, par3bench.ReferenceBuildOptions{
			Lock: lock, Out: filepath.Join(nfsrig.Cache, "ref"), Cache: filepath.Join(nfsrig.Cache, "ref-archive"),
			MirrorBase: os.Getenv("RARPAR_TOOL_MIRROR_BASE"), Log: os.Stderr,
		})
		if err != nil {
			return err
		}
		binaries.Reference = build.Binary
	}
	session, err := nfsrig.Mount(ctx, config, os.Stderr)
	if err != nil {
		return err
	}
	defer session.Close()
	suiteArgs := []string{"--reference", binaries.Reference, "--candidate", binaries.Candidate,
		"--engine-perf", binaries.EnginePerf, "--machine", "nfs-rig"}
	suiteArgs = append(append(suiteArgs, session.TargetArgs()...), suite...)
	if out := flagValue(suite, "out"); out != "" {
		if err := os.MkdirAll(out, 0o755); err != nil {
			return err
		}
		rig := map[string]any{"client": config, "markers": session.Markers, "local_fs": session.LocalFS, "suite_args": suiteArgs}
		data, err := json.MarshalIndent(rig, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "rig.json"), append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "nfs client: par3 run %v\n", suiteArgs)
	return runPAR3Suite(ctx, suiteArgs, stdout)
}

// flagValue is the last value of --name in args (either --name V or --name=V).
func flagValue(args []string, name string) string {
	value := ""
	for i, arg := range args {
		switch {
		case (arg == "--"+name || arg == "-"+name) && i+1 < len(args):
			value = args[i+1]
		case len(arg) > len(name)+3 && (arg[:len(name)+3] == "--"+name+"="):
			value = arg[len(name)+3:]
		}
	}
	return value
}
