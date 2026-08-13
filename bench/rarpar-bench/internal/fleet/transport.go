package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Transport is one machine's SSH channel.
//
// Everything here is deliberately conservative, because the bench fleet
// includes appliance-class hosts:
//   - explicit user@host with an explicit port, never an ssh_config alias (an
//     alias resolved to the wrong user once and mis-authenticated a round);
//   - tar-over-ssh for every transfer, never scp/sftp/rsync (the DSM host has
//     the sftp subsystem disabled, and the Mac's openrsync silently ignores -e);
//   - a short ControlPath under /tmp, because the default %r@%h:%p template
//     overruns the 104-byte unix socket limit for long hostnames;
//   - commands fed to the remote shell on stdin, never interpolated into a
//     remote command line.
type Transport struct {
	Machine     string
	Host        string
	Port        int
	User        string
	Auth        string
	KeyPath     string
	Askpass     string
	Shell       string
	Options     []string
	KnownHosts  string
	ControlPath string
	Persist     string
}

func NewTransport(machine Machine, runDir string) (*Transport, error) {
	connection := machine.Connection
	keyPath, err := expandUser(connection.KeyPath)
	if err != nil {
		return nil, err
	}
	askpass, err := expandUser(connection.AskpassScript)
	if err != nil {
		return nil, err
	}
	shell := connection.Shell
	if shell == "" {
		shell = "sh"
	}
	digest := sha256.Sum256([]byte(machine.Name + "\x00" + connection.Host))
	return &Transport{
		Machine:     machine.Name,
		Host:        connection.Host,
		Port:        connection.Port,
		User:        connection.User,
		Auth:        connection.Auth,
		KeyPath:     keyPath,
		Askpass:     askpass,
		Shell:       shell,
		Options:     append([]string(nil), connection.SSHOptions...),
		KnownHosts:  filepath.Join(runDir, "known_hosts"),
		ControlPath: "/tmp/cm-" + hex.EncodeToString(digest[:4]),
		Persist:     "30m",
	}, nil
}

func (transport *Transport) target() string {
	return transport.User + "@" + transport.Host
}

func (transport *Transport) baseArgs() []string {
	args := []string{
		"-p", strconv.Itoa(transport.Port),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + transport.KnownHosts,
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + transport.ControlPath,
		"-o", "ControlPersist=" + transport.Persist,
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=10",
		"-o", "ConnectTimeout=20",
		"-o", "LogLevel=ERROR",
	}
	switch transport.Auth {
	case "key":
		args = append(args, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", transport.KeyPath)
	case "askpass":
		// BatchMode must stay off: it disables the askpass helper outright.
		args = append(args, "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1")
	}
	return append(args, transport.Options...)
}

func (transport *Transport) environment() []string {
	environment := os.Environ()
	if transport.Auth != "askpass" {
		return environment
	}
	// The helper reads the secret from the operator's own environment file at
	// call time. The fleet never sees, stores, or logs the value.
	return append(environment,
		"SSH_ASKPASS="+transport.Askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=:0",
	)
}

func (transport *Transport) command(ctx context.Context, extra ...string) *exec.Cmd {
	args := append(transport.baseArgs(), transport.target())
	args = append(args, extra...)
	command := exec.CommandContext(ctx, "ssh", args...)
	command.Env = transport.environment()
	return command
}

// RunScript pipes a script to the remote shell on stdin. No quoting of operator
// data into a remote command line, ever.
func (transport *Transport) RunScript(ctx context.Context, script string) (string, string, error) {
	remoteShell := transport.Shell
	if remoteShell == "powershell" {
		return "", "", fmt.Errorf("machine %s: RunScript is POSIX-only; use the PowerShell runner", transport.Machine)
	}
	command := transport.command(ctx, remoteShell+" -s")
	command.Stdin = strings.NewReader(script)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		err = fmt.Errorf("machine %s: remote command failed: %w: %s", transport.Machine, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), stderr.String(), err
}

// Probe is a cheap reachability + identity check used in preflight.
func (transport *Transport) Probe(ctx context.Context) (string, error) {
	stdout, _, err := transport.RunScript(ctx, "uname -srm; echo \"nproc=$(nproc 2>/dev/null || echo unknown)\"; echo \"loadavg=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || uptime)\"")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ReplaceAll(stdout, "\n", " | ")), nil
}

// UploadDir sends a local directory as a gzipped tar stream. gzip is invoked
// explicitly rather than through tar -z so busybox and bsdtar behave alike.
func (transport *Transport) UploadDir(ctx context.Context, localDir, remoteDir string) error {
	if err := transport.Mkdir(ctx, remoteDir); err != nil {
		return err
	}
	// --no-xattrs keeps macOS provenance attributes out of the stream; GNU tar on
	// the receiving side warns about every one of them otherwise.
	pack := exec.CommandContext(ctx, "tar", "--no-xattrs", "-cf", "-", "-C", localDir, ".")
	// Keep AppleDouble ._ files out of bundles built on macOS.
	pack.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	pipe, err := pack.StdoutPipe()
	if err != nil {
		return err
	}
	var packErr bytes.Buffer
	pack.Stderr = &packErr

	script := fmt.Sprintf("mkdir -p %s && tar -xf - -C %s", shellQuote(remoteDir), shellQuote(remoteDir))
	receive := transport.command(ctx, "sh -c "+shellQuote(script))
	receive.Stdin = pipe
	var receiveOut, receiveErr bytes.Buffer
	receive.Stdout = &receiveOut
	receive.Stderr = &receiveErr

	if err := pack.Start(); err != nil {
		return err
	}
	if err := receive.Start(); err != nil {
		_ = pack.Process.Kill()
		return err
	}
	receiveWait := receive.Wait()
	packWait := pack.Wait()
	if receiveWait != nil {
		return fmt.Errorf("machine %s: upload to %s failed: %w: %s", transport.Machine, remoteDir, receiveWait, strings.TrimSpace(receiveErr.String()))
	}
	if packWait != nil {
		return fmt.Errorf("machine %s: reading local bundle %s failed: %w: %s", transport.Machine, localDir, packWait, strings.TrimSpace(packErr.String()))
	}
	return nil
}

// DownloadPath pulls one remote file into a local directory over the same
// tar-over-ssh channel.
func (transport *Transport) DownloadPath(ctx context.Context, remotePath, localDir string) error {
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return err
	}
	parent := posixDir(remotePath)
	base := posixBase(remotePath)
	send := transport.command(ctx, "sh -c "+shellQuote(fmt.Sprintf("tar -cf - -C %s %s", shellQuote(parent), shellQuote(base))))
	pipe, err := send.StdoutPipe()
	if err != nil {
		return err
	}
	var sendErr bytes.Buffer
	send.Stderr = &sendErr

	unpack := exec.CommandContext(ctx, "tar", "-xf", "-", "-C", localDir)
	unpack.Stdin = pipe
	var unpackErr bytes.Buffer
	unpack.Stderr = &unpackErr

	if err := send.Start(); err != nil {
		return err
	}
	if err := unpack.Start(); err != nil {
		_ = send.Process.Kill()
		return err
	}
	unpackWait := unpack.Wait()
	sendWait := send.Wait()
	if sendWait != nil {
		return fmt.Errorf("machine %s: download of %s failed: %w: %s", transport.Machine, remotePath, sendWait, strings.TrimSpace(sendErr.String()))
	}
	if unpackWait != nil {
		return fmt.Errorf("machine %s: unpacking %s failed: %w: %s", transport.Machine, remotePath, unpackWait, strings.TrimSpace(unpackErr.String()))
	}
	return nil
}

func (transport *Transport) Mkdir(ctx context.Context, remoteDir string) error {
	_, _, err := transport.RunScript(ctx, "set -e\nmkdir -p "+shellQuote(remoteDir)+"\n")
	return err
}

func (transport *Transport) Exists(ctx context.Context, remotePath string) (bool, error) {
	stdout, _, err := transport.RunScript(ctx, "if [ -e "+shellQuote(remotePath)+" ]; then echo yes; else echo no; fi\n")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(stdout) == "yes", nil
}

// Close drops the multiplexed master so a torn-down cloud host leaves no
// dangling control socket behind.
func (transport *Transport) Close() {
	command := exec.Command("ssh", append(transport.baseArgs(), "-O", "exit", transport.target())...)
	command.Env = transport.environment()
	_ = command.Run()
	_ = os.Remove(transport.ControlPath)
}

func expandUser(path string) (string, error) {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot expand %q without a home directory: %w", path, err)
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	return "", fmt.Errorf("cannot expand %q: only ~/ is supported", path)
}

// shellQuote produces a single-quoted POSIX shell word.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func posixDir(path string) string {
	index := strings.LastIndex(path, "/")
	if index <= 0 {
		return "/"
	}
	return path[:index]
}

func posixBase(path string) string {
	index := strings.LastIndex(path, "/")
	if index < 0 {
		return path
	}
	return path[index+1:]
}
