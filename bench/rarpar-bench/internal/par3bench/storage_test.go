package par3bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMountInfo = `22 1 0:21 / / rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u
40 22 0:40 / /w rw,relatime - ext4 /dev/vda1 rw
41 22 0:41 / /na rw,relatime - nfs4 nfs-server:/export/async rw,vers=4.1,rsize=1048576
42 22 0:42 / /ns rw,relatime - nfs4 nfs-server:/export/sync rw,vers=4.1,rsize=1048576
43 22 0:43 / /with\040space rw - tmpfs tmpfs rw
`

func TestParseMountInfoAndMountFor(t *testing.T) {
	mounts := ParseMountInfo(sampleMountInfo)
	if len(mounts) != 5 {
		t.Fatalf("parsed %d mounts, want 5", len(mounts))
	}
	cases := map[string]string{"/na/x/y": "/na", "/ns": "/ns", "/w/a": "/w", "/nax": "/", "/with space/f": "/with space"}
	for path, want := range cases {
		mount, ok := MountFor(mounts, path)
		if !ok || mount.MountPoint != want {
			t.Errorf("MountFor(%q) = %q, %v; want %q", path, mount.MountPoint, ok, want)
		}
	}
	mount, _ := MountFor(mounts, "/na/x")
	if mount.FSType != "nfs4" || mount.Source != "nfs-server:/export/async" || !strings.Contains(mount.SuperOptions, "vers=4.1") {
		t.Errorf("nfs mount fields = %+v", mount)
	}
}

const sampleMountStats = `device overlay mounted on / with fstype overlay
device nfs-server:/export/async mounted on /na with fstype nfs4 statvers=1.1
	opts:	rw,vers=4.1,rsize=1048576,wsize=1048576,hard,proto=tcp
	age:	12
	bytes:	1000 2000 0 0 3000 4000 10 20
	RPC iostats version: 1.1  p/v: 100003/4 (nfs)
	per-op statistics
	        NULL: 1 1 0 44 24 0 0 0 0
	        READ: 10 10 0 1600 10485760 3 40 45 0
	       WRITE: 4 4 0 4194304 640 1 20 22 0
	      COMMIT: 2 2 0 300 200 0 5 6 0
	     GETATTR: 7 7 0 900 1400 0 2 3 0
device nfs-server:/export/sync mounted on /ns with fstype nfs4 statvers=1.1
	opts:	rw,vers=4.1,sync
	bytes:	1 1 0 0 1 1 1 1
	per-op statistics
	        READ: 99 99 0 0 0 0 0 0 0
`

func TestParseMountStatsTakesOnlyTheNamedMount(t *testing.T) {
	stats, ok := ParseMountStats(sampleMountStats, "/na")
	if !ok {
		t.Fatal("no stats for /na")
	}
	if got := stats.Op("READ"); got != 10 {
		t.Errorf("READ ops = %d, want 10", got)
	}
	if read := stats.Ops["READ"]; read.BytesRecv != 10485760 || read.RTTMS != 40 || read.ExecuteMS != 45 {
		t.Errorf("READ = %+v", read)
	}
	if stats.NormalReadBytes != 1000 || stats.NormalWriteBytes != 2000 || stats.ServerReadBytes != 3000 || stats.ServerWriteBytes != 4000 {
		t.Errorf("bytes = %+v", stats)
	}
	if !strings.Contains(stats.Options, "rsize=1048576") {
		t.Errorf("options = %q", stats.Options)
	}
	if _, ok := ParseMountStats(sampleMountStats, "/missing"); ok {
		t.Error("stats for a mount that is not there")
	}
	sync, _ := ParseMountStats(sampleMountStats, "/ns")
	if sync.Op("READ") != 99 {
		t.Errorf("/ns READ = %d", sync.Op("READ"))
	}
}

func TestNFSStatsDeltaKeepsOnlyMovedOps(t *testing.T) {
	before, _ := ParseMountStats(sampleMountStats, "/na")
	after, _ := ParseMountStats(strings.Replace(sampleMountStats, "READ: 10 10 0 1600 10485760", "READ: 15 15 0 2400 15728640", 1), "/na")
	delta := after.Sub(before)
	if delta.Op("READ") != 5 || delta.Ops["READ"].BytesRecv != 5242880 {
		t.Errorf("READ delta = %+v", delta.Ops["READ"])
	}
	if len(delta.Ops) != 1 {
		t.Errorf("delta keeps unmoved ops: %v", delta.Ops)
	}
	if delta.TotalOps() != 5 {
		t.Errorf("TotalOps = %d", delta.TotalOps())
	}
}

func TestParseTargetAndMeta(t *testing.T) {
	targets := []Target{}
	for _, text := range []string{"local=/w", "nfs-async=/na"} {
		target, err := ParseTarget(text)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	for _, bad := range []string{"=/w", "x=", "a/b=/w", "a@b=/w", "noequals"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) accepted", bad)
		}
	}
	if err := ApplyTargetMeta(targets, "nfs-async:server=kernel-nfsd,export=async"); err != nil {
		t.Fatal(err)
	}
	if targets[1].Meta["server"] != "kernel-nfsd" || targets[1].Meta["export"] != "async" || targets[0].Meta != nil {
		t.Errorf("meta = %+v", targets)
	}
	for _, bad := range []string{"other:a=b", "nfs-async:novalue", "nfs-async:"} {
		if err := ApplyTargetMeta(targets, bad); err == nil {
			t.Errorf("ApplyTargetMeta(%q) accepted", bad)
		}
	}
}

func TestMatrixRowsExpandPerTargetAndFilterKinds(t *testing.T) {
	targets := []Target{{Name: "local", Work: "/w"}, {Name: "nfs", Work: "/na"}}
	rows := MatrixRows([]int{8}, nil, []string{DurabilityDurable}, []int{8},
		[]KernelVariant{{Name: "wff-off", Env: []string{"PAR3_BENCH_WHOLE_FILE_FIRST=0"}}}, []string{ToolEngine}, targets)
	var names []string
	for _, row := range rows {
		names = append(names, row.Name)
		if row.Tool != ToolEngine {
			t.Errorf("row %s has tool %s", row.Name, row.Tool)
		}
	}
	want := "engine-w8@local engine-w8-wff-off@local engine-w8@nfs engine-w8-wff-off@nfs"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("rows = %s\nwant   %s", got, want)
	}
	if rows[1].dirName() != "engine-w8-wff-off" {
		t.Errorf("dirName = %s", rows[1].dirName())
	}
	single := MatrixRows([]int{1}, nil, []string{DurabilityDurable}, nil, nil, nil, nil)
	if len(single) != 2 || single[0].Name != "reference" || single[1].Name != "rarpar-w1" {
		t.Errorf("untargeted rows = %+v", single)
	}
	buffered := EngineRows([]int{8}, nil, nil)
	if len(buffered) != 2 || buffered[1].Name != "engine-w8-buffered" {
		t.Errorf("engine durability rows = %+v", buffered)
	}
}

func TestEngineCommandPassesBufferedDurabilityPerOp(t *testing.T) {
	r := &runner{options: Options{EnginePerf: "/bin/engine_perf", EnginePerfMemoryMiB: 256}, results: &Results{}}
	config := Config{Codec: "cauchy", BlockSize: 1 << 20, Recovery: 52}
	command := r.engineCommand(OpRepair, config, "/d", "/s/repair-engine-w8", Variant{Workers: 8, Durability: DurabilityBuffered})
	if strings.Join(command.Args, " ") != "repair /s/repair-engine-w8 /s/repair-engine-w8 /s/repair-engine-w8 8 256" {
		t.Errorf("args = %v", command.Args)
	}
	if len(command.Env) != 1 || command.Env[0] != "PAR3_BENCH_REPAIR_DURABILITY=buffered" || command.Dir != "/s" {
		t.Errorf("env = %v dir = %s", command.Env, command.Dir)
	}
	create := r.engineCommand(OpCreate, config, "/d", "/s/c", Variant{Workers: 1})
	if strings.Join(create.Args, " ") != "create /d /s/c /s/c-spool 1 256 cauchy 1048576 52 0" || len(create.Env) != 0 {
		t.Errorf("create = %v %v", create.Args, create.Env)
	}
}

func TestParseEngineOutput(t *testing.T) {
	stdout := `{"whole_file_first":false}
{"status":"Ready"}
{"internal_stage":"Sync","seconds":0.25}
{"stripe_passes":3}
{"file_read_bytes":1048576,"file_read_calls":4,"file_write_bytes":2048,"file_write_calls":2,"file_opens":9,"file_syncs":5,"file_clones":0,"snapshots":1}
`
	counters, ok := ParseEngineOutput(stdout)
	if !ok {
		t.Fatal("totals not found")
	}
	if counters.ReadBytes != 1048576 || counters.ReadCalls != 4 || counters.WriteBytes != 2048 || counters.Opens != 9 || counters.Syncs != 5 || counters.Snapshots != 1 {
		t.Errorf("counters = %+v", counters)
	}
	if counters.WholeFileFirst == nil || *counters.WholeFileFirst || counters.Status != "Ready" || counters.SyncSeconds != 0.25 || counters.StripePasses != 3 {
		t.Errorf("counters = %+v", counters)
	}
	if _, ok := ParseEngineOutput(`{"status":"Ready"}`); ok {
		t.Error("totals found in output without them")
	}
}

func TestVerifyDamagedStageLinksTheSharedDamagedInputs(t *testing.T) {
	root := t.TempDir()
	dataDir, damaged, canonical := filepath.Join(root, "d"), filepath.Join(root, "x"), filepath.Join(root, "c")
	for _, dir := range []string{dataDir, damaged, canonical} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dataset := Dataset{Files: []FileSpec{{Name: "a.bin", Size: 4}}}
	for dir, content := range map[string]string{dataDir: "good", damaged: "bad!"} {
		if err := os.WriteFile(filepath.Join(dir, "a.bin"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(canonical, "set.par3"), []byte("p"), 0o644); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "s")
	if err := stageFrom(stageDir, dataset, dataDir, canonical, Config{}, OpVerifyDamaged, damaged); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stageDir, "a.bin"))
	if err != nil || string(data) != "bad!" {
		t.Errorf("staged input = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(stageDir, "set.par3")); err != nil {
		t.Error(err)
	}
}

func TestEngineBufferedRowsDoNotNeedTheCLIFlag(t *testing.T) {
	r := &runner{results: &Results{BufferedArgs: map[string][]string{}}}
	engine := Variant{Name: "engine-w8-buffered", Tool: ToolEngine, Workers: 8, Durability: DurabilityBuffered}
	cli := Variant{Name: "rarpar-w8-buffered", Tool: ToolCandidate, Workers: 8, Durability: DurabilityBuffered}
	if !r.runsOp(engine, OpRepair) {
		t.Error("engine buffered repair row dropped when the CLI has no --buffered")
	}
	if r.runsOp(cli, OpRepair) {
		t.Error("CLI buffered repair row kept without a --buffered flag")
	}
	if r.runsOp(engine, OpVerify) {
		t.Error("buffered row for a read-only op")
	}
}
