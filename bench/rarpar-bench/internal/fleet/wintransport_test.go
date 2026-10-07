package fleet

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata/windows")

// checkGolden compares generated PowerShell with testdata/windows/<name>.
// Regenerate with: go test ./internal/fleet -run Golden -update
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "windows", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from the golden file; rerun with -update if the change is intended.\n--- got ---\n%s", path, got)
	}
}

func windowsExample(t *testing.T) (Config, Machine) {
	t.Helper()
	config := loadExample(t)
	for _, machine := range config.Machines {
		if machine.Name == "win-dgpu" {
			return config, machine
		}
	}
	t.Fatal("example config has no win-dgpu machine")
	return config, Machine{}
}

func decodePowerShell(t *testing.T, line string) string {
	t.Helper()
	const flagName = "-EncodedCommand "
	index := strings.Index(line, flagName)
	if index < 0 {
		t.Fatalf("no -EncodedCommand in %q", line)
	}
	raw, err := base64.StdEncoding.DecodeString(line[index+len(flagName):])
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("odd UTF-16LE payload length %d", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(units))
}

func TestWindowsPowerShellGolden(t *testing.T) {
	config, machine := windowsExample(t)
	layout := windowsLayout(machine, "fleet-testrun")
	checkGolden(t, "run.ps1", WindowsRunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout,
		map[string]string{"rar": `C:\bench\oracles\UnRAR.exe`, "par3": `C:\bench\fleet-stage\fleet-testrun\oracles\par3.exe`}))
	checkGolden(t, "probe.ps1", psProbeScript())
	checkGolden(t, "mkdir.ps1", psMkdirScript(layout.Bin))
	checkGolden(t, "exists.ps1", psExistsScript(layout.Done))
	checkGolden(t, "read-sentinel.ps1", psReadOptionalScript(layout.Done, readMissingMarker))
	checkGolden(t, "expand-upload.ps1", psExpandArchiveScript(layout.Bin+`\fleet-upload.zip`, layout.Bin))
	checkGolden(t, "cleanup.ps1", psRemoveAllScript(layout.Base, layout.Scratch))
	checkGolden(t, "oracle-check.ps1", psOracleCheckScript(`C:\bench\oracles\O'Brien\UnRAR.exe`))
	checkGolden(t, "start-detached.ps1", psStartDetachedScript(layout.Script, layout.Log, layout.Base))

	// The wrapper every control script travels in.
	line, err := powerShellCommandLine(psMkdirScript(layout.Bin))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(line, `"'%&|<>^`) {
		t.Fatalf("the remote command line must carry nothing cmd.exe interprets: %s", line)
	}
	checkGolden(t, "wrapped-mkdir.ps1", decodePowerShell(t, line))
}

func TestWindowsRunScriptUsesNoPOSIXTools(t *testing.T) {
	config, machine := windowsExample(t)
	layout := windowsLayout(machine, "fleet-testrun")
	if !strings.HasSuffix(layout.Tarball, `\results.zip`) {
		t.Fatalf("Windows evidence must be a zip: %s", layout.Tarball)
	}
	script := WindowsRunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout, nil)
	for _, forbidden := range []string{"tar.exe", "tar -", " sh ", "bash"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("the Windows run script must not use %q", forbidden)
		}
	}
	if !strings.Contains(script, "$ProgressPreference = 'SilentlyContinue'") {
		t.Fatal("the run script must silence progress records")
	}
}

func TestPowerShellCommandIsBudgeted(t *testing.T) {
	if _, err := powerShellCommandLine(strings.Repeat("x", 6000)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("an over-long control script must be refused, not truncated: %v", err)
	}
	if got := scpPath(`C:\bench\fleet-stage\r1\results.zip`); got != "/C:/bench/fleet-stage/r1/results.zip" {
		t.Fatalf("scpPath = %s", got)
	}
	if got := remoteBase(`C:\bench\r1\results.zip`); got != "results.zip" {
		t.Fatalf("remoteBase(windows) = %s", got)
	}
	if got := remoteBase("/srv/bench/r1/results.tar.gz"); got != "results.tar.gz" {
		t.Fatalf("remoteBase(posix) = %s", got)
	}
}

func TestWindowsPathsRefuseCmdMetacharacters(t *testing.T) {
	for _, value := range []string{`C:\bench\100%`, `C:\be"nch`, "C:\\bench\nx"} {
		state := &decodeState{}
		validateHostPath(state, "machines[0]", "paths.staging", value, true)
		if len(state.errors) == 0 {
			t.Fatalf("%q must be refused on a Windows host", value)
		}
	}
	state := &decodeState{}
	validateHostPath(state, "machines[0]", "paths.staging", `C:\bench\O'Brien`, true)
	if len(state.errors) != 0 {
		t.Fatalf("a single quote is escaped, not refused: %v", state.errors)
	}

	// ...and it is escaped everywhere it lands: the run script and every
	// control script quote it as O''Brien and never leave it bare.
	config, machine := windowsExample(t)
	machine.Name = "win-$(evil)'x"
	machine.PlatformLabel = "label'$env:X"
	machine.Paths.Staging = `C:\bench\O'Brien`
	machine.Paths.Scratch = `C:\bench\O'Brien\work`
	machine.Paths.Corpus = `C:\bench\O'Brien\corpus`
	machine.PAR3.Work = `C:\p3\O'Brien`
	layout := windowsLayout(machine, "fleet-testrun")
	oracle := `C:\bench\O'Brien\oracles\par3.exe`
	scripts := map[string]string{
		"run":     WindowsRunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{"rar": oracle, "par2": oracle, "par3": oracle}),
		"mkdir":   psMkdirScript(layout.Bin),
		"exists":  psExistsScript(layout.Done),
		"read":    psReadOptionalScript(layout.Done, readMissingMarker),
		"expand":  psExpandArchiveScript(layout.Bin+`\fleet-upload.zip`, layout.Bin),
		"cleanup": psRemoveAllScript(layout.Base, layout.Scratch),
		"oracle":  psOracleCheckScript(oracle),
		"start":   psStartDetachedScript(layout.Script, layout.Log, layout.Base),
	}
	for name, script := range scripts {
		if !strings.Contains(script, "O''Brien") {
			t.Fatalf("%s script does not carry the quoted path:\n%s", name, script)
		}
		if strings.Contains(strings.ReplaceAll(script, "O''Brien", ""), "O'Brien") {
			t.Fatalf("%s script leaves a single quote unescaped:\n%s", name, script)
		}
	}
	run := scripts["run"]
	if !strings.Contains(run, `$MachineName = 'win-$(evil)''x'`) || !strings.Contains(run, `$Machine = 'label''$env:X'`) {
		t.Fatalf("machine name and label must be single-quoted literals:\n%s", run)
	}
	if strings.Contains(run, `"machine=`) {
		t.Fatal("the machine name must not sit inside an expandable double-quoted string")
	}
	for _, line := range strings.Split(run, "\r\n") {
		for _, cmdlet := range []string{"Remove-Item ", "Get-ChildItem ", "Copy-Item ", "Move-Item ", "Get-FileHash ", "Test-Path ", "Get-Item ", "Out-File "} {
			index := strings.Index(line, cmdlet)
			if index >= 0 && !strings.HasPrefix(line[index+len(cmdlet):], "-LiteralPath") && !strings.HasPrefix(line[index+len(cmdlet):], "-Algorithm SHA256 -LiteralPath") {
				t.Fatalf("%s must take -LiteralPath: %s", strings.TrimSpace(cmdlet), line)
			}
		}
	}
}

// Windows PowerShell 5.1 writes UTF-8 with a BOM; the collected manifest must
// still parse.
func TestReadJSONFileStripsAUTF8BOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "MANIFEST.json")
	if err := os.WriteFile(path, append([]byte{0xEF, 0xBB, 0xBF}, `{"run_id":"r1","status":"ok"}`...), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := &HostManifest{}
	if err := readJSONFile(path, manifest); err != nil {
		t.Fatalf("a BOM-prefixed manifest must parse: %v", err)
	}
	if manifest.RunID != "r1" || manifest.Status != "ok" {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestExtractZipNormalisesAndContains(t *testing.T) {
	build := func(names ...string) string {
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		for _, name := range names {
			entry, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = entry.Write([]byte(name))
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "results.zip")
		if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	destination := t.TempDir()
	if err := extractEvidence(build(`MANIFEST.json`, `par3\report.md`), destination); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "par3", "report.md")); err != nil || string(data) != `par3\report.md` {
		t.Fatalf("backslash entry names must extract into subdirectories: %v %q", err, data)
	}
	for _, hostile := range []string{`..\escape.txt`, "../escape.txt", "/abs.txt"} {
		if err := extractZip(build(hostile), t.TempDir()); err == nil {
			t.Fatalf("%q must be refused", hostile)
		}
	}
}

// fakeRemote puts stand-in ssh and scp on PATH that log their argv and, for
// ssh, decode nothing: the test decodes the logged -EncodedCommand itself.
func fakeRemote(t *testing.T, sshStdout string) (logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stand-in binaries are POSIX shell scripts")
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	for _, tool := range []string{"ssh", "scp"} {
		script := "#!/bin/sh\nprintf '%s' \"" + tool + "\" >> \"" + logPath + "\"\nfor a in \"$@\"; do printf ' [%s]' \"$a\" >> \"" + logPath + "\"; done\necho >> \"" + logPath + "\"\n"
		if tool == "ssh" {
			script += "printf '%s' '" + sshStdout + "'\n"
		}
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestWindowsTransportUsesScpAndPowerShellOnly(t *testing.T) {
	_, machine := windowsExample(t)
	machine.Connection.Port = 2202
	machine.Connection.KeyPath = filepath.Join(t.TempDir(), "key")
	logPath := fakeRemote(t, "yes")
	transport, err := NewTransport(machine, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, "rarpar.exe"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := transport.UploadDir(ctx, local, `C:\bench\fleet-stage\r1\bin`); err != nil {
		t.Fatal(err)
	}
	if err := transport.DownloadPath(ctx, `C:\bench\fleet-stage\r1\results.zip`, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if found, err := transport.Exists(ctx, `C:\bench\fleet-stage\r1\DONE`); err != nil || !found {
		t.Fatalf("Exists = %v, %v", found, err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(calls) != 5 {
		t.Fatalf("want mkdir, scp up, expand, scp down, exists; got %d calls:\n%s", len(calls), data)
	}
	var scripts []string
	for _, call := range calls {
		if strings.Contains(call, "[sh") || strings.Contains(call, "tar") {
			t.Fatalf("the Windows transport must not run sh or tar: %s", call)
		}
		switch {
		case strings.HasPrefix(call, "scp "):
			if !strings.Contains(call, "[-P] [2202]") || strings.Contains(call, "[-p]") {
				t.Fatalf("scp must take the port as -P: %s", call)
			}
		case strings.HasPrefix(call, "ssh "):
			fields := strings.Split(call, " [")
			last := strings.TrimSuffix(fields[len(fields)-1], "]")
			if !strings.HasPrefix(last, "powershell.exe ") {
				t.Fatalf("every ssh command must be one powershell.exe -EncodedCommand: %s", call)
			}
			scripts = append(scripts, decodePowerShell(t, last))
		}
	}
	if !strings.Contains(calls[1], "[bench@203.0.113.30:/C:/bench/fleet-stage/r1/bin/fleet-upload.zip]") {
		t.Fatalf("upload target = %s", calls[1])
	}
	if !strings.Contains(calls[3], "[bench@203.0.113.30:/C:/bench/fleet-stage/r1/results.zip]") {
		t.Fatalf("download source = %s", calls[3])
	}
	if len(scripts) != 3 || !strings.Contains(scripts[0], "New-Item -ItemType Directory") ||
		!strings.Contains(scripts[1], "Expand-Archive") || !strings.Contains(scripts[2], "Test-Path") {
		t.Fatalf("unexpected control scripts: %q", scripts)
	}
	if _, _, err := transport.RunScript(ctx, "echo hi"); err == nil {
		t.Fatal("RunScript must refuse a powershell host")
	}
}

func TestWriteZipUsesForwardSlashes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sub/a.exe", "._junk", "b.json"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if err := writeZip(&buffer, root); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range reader.File {
		names = append(names, file.Name)
	}
	if got := strings.Join(names, ","); got != "b.json,sub/,sub/a.exe" {
		t.Fatalf("zip entries = %s", got)
	}
}

// PowerShell does not stop on a native command's non-zero exit, so every
// external command in the run script must be followed by a Check that fails
// the run with that step's exit code; otherwise a crashed step is collected
// as status=ok.
func TestWindowsRunScriptChecksEveryExternalExit(t *testing.T) {
	config, machine := windowsExample(t)
	for _, suite := range []string{SuiteCRCProbe, SuiteMacroPAR3} {
		if !machine.hasSuite(suite) {
			machine.Suites = append(machine.Suites, suite)
		}
	}
	layout := windowsLayout(machine, "fleet-testrun")
	script := WindowsRunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout,
		map[string]string{"rar": `C:\o\UnRAR.exe`, "par2": `C:\o\par2.exe`, "par3": `C:\o\par3.exe`})
	if !strings.Contains(script, "function Check($what) { if ($LASTEXITCODE -ne 0) { Fail ($what + ':exit-' + $LASTEXITCODE) } }") {
		t.Fatal("the run script must define Check over $LASTEXITCODE")
	}
	lines := strings.Split(script, "\r\n")
	external := 0
	for i, line := range lines {
		at := strings.Index(line, "& $")
		if at < 0 {
			continue
		}
		external++
		rest := line[at:]
		next := ""
		if i+1 < len(lines) {
			next = strings.TrimSpace(lines[i+1])
		}
		if !strings.Contains(rest, "; Check '") && !strings.HasPrefix(next, "Check '") {
			t.Errorf("external command without an exit check:\n%s\n%s", line, next)
		}
	}
	// crc_probe, and per family corpus verify, plan, run and report, and the
	// PAR3 suite.
	if external < 6 {
		t.Fatalf("found %d external commands; the script shape changed:\n%s", external, script)
	}
}
