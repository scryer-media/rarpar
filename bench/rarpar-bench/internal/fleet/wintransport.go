package fleet

// Windows transport: Windows OpenSSH plus Windows PowerShell 5.1, nothing else.
//
// UNVALIDATED: this has never run against a live Windows host. It is unit
// tested against golden files (testdata/windows/*) and with stand-in ssh/scp
// binaries, so the argument shape and the generated PowerShell are pinned,
// but no Windows sshd has executed any of it yet.
//
// The far side is assumed to have no `sh` and no `tar`, so:
//   - control commands are short PowerShell scripts sent as
//     `powershell.exe ... -EncodedCommand <base64 of UTF-16LE>`. Base64 has no
//     characters that cmd.exe (OpenSSH's default shell) or PowerShell treats
//     specially, so there is no quoting layer to get wrong; a script that would
//     not fit cmd.exe's command-line limit is refused rather than truncated.
//     The run itself is never an inline command: it is an uploaded .ps1 FILE.
//   - files move by scp (Windows sshd ships the sftp subsystem). A directory is
//     zipped locally, sent as one file and unpacked with Expand-Archive.
//   - evidence comes back as results.zip, built on the host with
//     System.IO.Compression.ZipFile and fetched by scp.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// powerShellCommandLimit keeps the whole remote command line under cmd.exe's
// 8191-character limit with room for the ssh-side wrapping.
const powerShellCommandLimit = 8000

// powerShellPrelude starts every generated script. Progress records otherwise
// arrive on stderr as CLIXML when powershell.exe has no console.
const powerShellPrelude = "$ProgressPreference = 'SilentlyContinue'\r\n"

func (transport *Transport) windows() bool { return transport.Shell == "powershell" }

// psQuote produces a single-quoted PowerShell string literal.
func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// encodePowerShell is the -EncodedCommand payload: base64 of UTF-16LE.
func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// powerShellCommandLine is the exact remote command for one control script.
// Errors become a non-zero exit with the message on stderr.
func powerShellCommandLine(script string) (string, error) {
	body := powerShellPrelude +
		"$ErrorActionPreference = 'Stop'\r\n" +
		"try {\r\n" + script + "\r\n} catch {\r\n  [Console]::Error.WriteLine($_.Exception.Message)\r\n  exit 1\r\n}\r\n"
	line := "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodePowerShell(body)
	if len(line) > powerShellCommandLimit {
		return "", fmt.Errorf("generated PowerShell command is %d characters, over the %d-character cmd.exe budget; upload it as a .ps1 instead", len(line), powerShellCommandLimit)
	}
	return line, nil
}

// RunPowerShell runs one short control script on a Windows host.
func (transport *Transport) RunPowerShell(ctx context.Context, script string) (string, string, error) {
	if !transport.windows() {
		return "", "", fmt.Errorf("machine %s: RunPowerShell needs a powershell host", transport.Machine)
	}
	line, err := powerShellCommandLine(script)
	if err != nil {
		return "", "", fmt.Errorf("machine %s: %w", transport.Machine, err)
	}
	command := transport.command(ctx, line)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	if err != nil {
		err = fmt.Errorf("machine %s: remote PowerShell failed: %w: %s", transport.Machine, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), stderr.String(), err
}

// The control scripts. Each is a pure function so the golden files pin them.

func psProbeScript() string {
	return strings.Join([]string{
		"$os = Get-CimInstance Win32_OperatingSystem",
		"$load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average",
		"Write-Output (\"{0} {1} {2}\" -f $os.Caption, $os.Version, $env:PROCESSOR_ARCHITECTURE)",
		"Write-Output (\"nproc={0}\" -f $env:NUMBER_OF_PROCESSORS)",
		"Write-Output (\"cpu_load_percent={0}\" -f $load)",
	}, "\r\n")
}

func psMkdirScript(path string) string {
	return "New-Item -ItemType Directory -Force -Path " + psQuote(path) + " | Out-Null"
}

func psExistsScript(path string) string {
	return "if (Test-Path -LiteralPath " + psQuote(path) + ") { 'yes' } else { 'no' }"
}

func psRemoveAllScript(paths ...string) string {
	lines := make([]string, 0, len(paths))
	for _, path := range paths {
		lines = append(lines, "if (Test-Path -LiteralPath "+psQuote(path)+") { Remove-Item -LiteralPath "+psQuote(path)+" -Recurse -Force }")
	}
	return strings.Join(lines, "\r\n")
}

// psReadOptionalScript prints the file, or the marker when it is absent.
func psReadOptionalScript(path, marker string) string {
	return "if (Test-Path -LiteralPath " + psQuote(path) + " -PathType Leaf) { [IO.File]::ReadAllText(" + psQuote(path) + ") } else { " + psQuote(marker) + " }"
}

func psExpandArchiveScript(archive, destination string) string {
	return strings.Join([]string{
		"New-Item -ItemType Directory -Force -Path " + psQuote(destination) + " | Out-Null",
		"Expand-Archive -LiteralPath " + psQuote(archive) + " -DestinationPath " + psQuote(destination) + " -Force",
		"Remove-Item -LiteralPath " + psQuote(archive) + " -Force",
	}, "\r\n")
}

// psOracleCheckScript answers MISSING or the lower-case sha256 of the file.
func psOracleCheckScript(path string) string {
	return "if (-not (Test-Path -LiteralPath " + psQuote(path) + " -PathType Leaf)) { 'MISSING' } else { (Get-FileHash -Algorithm SHA256 -LiteralPath " + psQuote(path) + ").Hash.ToLower() }"
}

// psStartDetachedScript starts the uploaded .ps1 through Win32_Process.Create.
// The WMI provider host is the parent, so the run is outside the sshd
// session's job object and survives the connection closing (a Start-Process
// child is killed with the session). cmd.exe redirects all output to the log.
func psStartDetachedScript(script, log, workdir string) string {
	commandLine := `cmd.exe /d /s /c ""powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "` + script + `" > "` + log + `" 2>&1"`
	return strings.Join([]string{
		"$result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = " + psQuote(commandLine) + "; CurrentDirectory = " + psQuote(workdir) + " }",
		"if ($result.ReturnValue -ne 0) { throw (\"Win32_Process.Create returned {0}\" -f $result.ReturnValue) }",
		"Write-Output (\"pid={0}\" -f $result.ProcessId)",
	}, "\r\n")
}

// scpPath turns C:\a\b into /C:/a/b, the absolute form Windows OpenSSH's
// sftp-server accepts.
func scpPath(windowsPath string) string {
	path := strings.ReplaceAll(windowsPath, `\`, "/")
	if len(path) >= 2 && path[1] == ':' {
		path = "/" + path
	}
	return path
}

// scpArgs reuses the ssh options (multiplexing, known hosts, auth) with scp's
// -P spelling of the port.
func (transport *Transport) scpArgs() []string {
	args := transport.baseArgs()
	out := make([]string, 0, len(args)+1)
	for index := 0; index < len(args); index++ {
		if args[index] == "-p" && index+1 < len(args) {
			out = append(out, "-P", args[index+1])
			index++
			continue
		}
		out = append(out, args[index])
	}
	return append(out, "-q")
}

func (transport *Transport) scp(ctx context.Context, from, to string) error {
	args := append(transport.scpArgs(), from, to)
	command := exec.CommandContext(ctx, "scp", args...)
	command.Env = transport.environment()
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("machine %s: scp %s -> %s failed: %w: %s", transport.Machine, from, to, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (transport *Transport) uploadDirWindows(ctx context.Context, localDir, remoteDir string) error {
	archive, err := os.CreateTemp("", "rarpar-fleet-upload-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	if err := writeZip(archive, localDir); err != nil {
		archive.Close()
		return fmt.Errorf("machine %s: zipping %s: %w", transport.Machine, localDir, err)
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := transport.Mkdir(ctx, remoteDir); err != nil {
		return err
	}
	remoteZip := remoteDir + `\fleet-upload.zip`
	if err := transport.scp(ctx, archive.Name(), transport.target()+":"+scpPath(remoteZip)); err != nil {
		return err
	}
	if _, _, err := transport.RunPowerShell(ctx, psExpandArchiveScript(remoteZip, remoteDir)); err != nil {
		return fmt.Errorf("machine %s: unpacking the upload into %s: %w", transport.Machine, remoteDir, err)
	}
	return nil
}

func (transport *Transport) downloadPathWindows(ctx context.Context, remotePath, localDir string) error {
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return err
	}
	return transport.scp(ctx, transport.target()+":"+scpPath(remotePath), filepath.Join(localDir, remoteBase(remotePath)))
}

// writeZip stores a directory tree with forward-slash names, skipping macOS
// AppleDouble files.
func writeZip(out io.Writer, root string) error {
	writer := zip.NewWriter(out)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || strings.HasPrefix(entry.Name(), "._") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if entry.IsDir() {
			_, err := writer.Create(name + "/")
			return err
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files can be uploaded", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = name
		header.Method = zip.Deflate
		target, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		source, err := os.Open(path)
		if err != nil {
			return err
		}
		defer source.Close()
		_, err = io.Copy(target, source)
		return err
	})
	if err != nil {
		return err
	}
	return writer.Close()
}

// extractZip unpacks host evidence. Names are normalised from backslashes
// (.NET Framework's ZipFile wrote them on older hosts) and any entry that would
// land outside the destination is refused.
func extractZip(archive, destination string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		name := strings.ReplaceAll(file.Name, `\`, "/")
		target, err := containedPath(destination, name)
		if err != nil {
			return err
		}
		if strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractZipFile(file, target); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(file *zip.File, target string) error {
	source, err := file.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, source); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// remoteBase is the last element of a POSIX or Windows remote path.
func remoteBase(path string) string {
	index := strings.LastIndexAny(path, `/\`)
	if index < 0 {
		return path
	}
	return path[index+1:]
}

// extractEvidence unpacks a host's evidence archive by its format.
func extractEvidence(archive, destination string) error {
	if strings.HasSuffix(archive, ".zip") {
		return extractZip(archive, destination)
	}
	return extractTarGz(archive, destination)
}
