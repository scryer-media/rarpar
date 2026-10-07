package nfsrig

import (
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestExportsFileServesOneExportPerWriteMode(t *testing.T) {
	text := ExportsFile(Exports())
	want := "/export *(ro,fsid=0,crossmnt,no_subtree_check,no_root_squash,insecure)\n" +
		"/export/async *(rw,async,no_subtree_check,no_root_squash,insecure,fsid=11)\n" +
		"/export/sync *(rw,sync,no_subtree_check,no_root_squash,insecure,fsid=12)\n"
	if text != want {
		t.Errorf("exports =\n%s\nwant\n%s", text, want)
	}
}

func TestExportSourceFollowsTheProtocolVersion(t *testing.T) {
	export := Exports()[0]
	if got := export.Source("srv", "4.1"); got != "srv:/async" {
		t.Errorf("v4 source = %s", got)
	}
	if got := export.Source("srv", "3"); got != "srv:/export/async" {
		t.Errorf("v3 source = %s", got)
	}
	if got := exportOptions(export); got != "*(rw,async,no_subtree_check,no_root_squash,insecure,fsid=11)" {
		t.Errorf("export options = %s", got)
	}
}

func TestServerConfigNFSDArgs(t *testing.T) {
	config, err := ServerConfigFromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(config.NFSDArgs(), " "); got != "-V 3 -N 4.0 -V 4.1 -V 4.2 8" {
		t.Errorf("default args = %s", got)
	}
	config, err = ServerConfigFromEnv(env(map[string]string{"NFS_THREADS": "16", "NFS_SERVER_VERSIONS": "4, 4.2"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(config.NFSDArgs(), " "); got != "-N 3 -V 4.0 -N 4.1 -V 4.2 16" {
		t.Errorf("args = %s", got)
	}
	for _, bad := range []map[string]string{{"NFS_THREADS": "0"}, {"NFS_SERVER_VERSIONS": "5"}, {"NFS_SERVER_VERSIONS": ","}} {
		if _, err := ServerConfigFromEnv(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestMountOptionsFromEnv(t *testing.T) {
	config, err := MountConfigFromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Options(); got != "vers=4.1,proto=tcp,hard,rsize=1048576,wsize=1048576" || config.LocalIO {
		t.Errorf("default options = %s localio=%v", got, config.LocalIO)
	}
	config, err = MountConfigFromEnv(env(map[string]string{
		"NFS_VERS": "3", "NFS_RSIZE": "0", "NFS_WSIZE": "65536", "NFS_HARD": "soft", "NFS_ACTIMEO": "0",
		"NFS_CLIENT_SYNC": "sync", "NFS_NCONNECT": "4", "NFS_EXTRA_OPTS": ",noatime,", "NFS_LOCALIO": "on",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Options(); got != "vers=3,proto=tcp,soft,wsize=65536,actimeo=0,sync,nconnect=4,nolock,noatime" || !config.LocalIO {
		t.Errorf("options = %s localio=%v", got, config.LocalIO)
	}
	for _, bad := range []map[string]string{
		{"NFS_VERS": "5"}, {"NFS_RSIZE": "-1"}, {"NFS_HARD": "medium"}, {"NFS_ACTIMEO": "x"},
		{"NFS_CLIENT_SYNC": "maybe"}, {"NFS_NCONNECT": "17"}, {"NFS_LOCALIO": "yes please"},
	} {
		if _, err := MountConfigFromEnv(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestClientConfigSwitches(t *testing.T) {
	config, err := ClientConfigFromEnv(env(map[string]string{"RIG_BUILD": "off", "NFS_SERVER": "srv"}))
	if err != nil {
		t.Fatal(err)
	}
	if config.Build || !config.Reference || config.Server != "srv" {
		t.Errorf("config = %+v", config)
	}
	if _, err := ClientConfigFromEnv(env(map[string]string{"RIG_REFERENCE": "sometimes"})); err == nil {
		t.Error("accepted RIG_REFERENCE=sometimes")
	}
}

func TestClientConfigExt4Size(t *testing.T) {
	config, err := ClientConfigFromEnv(env(map[string]string{"RIG_EXT4": "8G"}))
	if err != nil || config.Ext4 != "8G" {
		t.Fatalf("config = %+v, err = %v", config, err)
	}
	for _, bad := range []string{"G", "8GB", "-8G", "8 G", "eight"} {
		if _, err := ClientConfigFromEnv(env(map[string]string{"RIG_EXT4": bad})); err == nil {
			t.Errorf("accepted RIG_EXT4=%q", bad)
		}
	}
	args := strings.Join(Ext4TargetArgs(), " ")
	if !strings.Contains(args, "local-ext4="+LocalExt4) || !strings.Contains(args, "backing_fs=ext4") {
		t.Errorf("ext4 target args = %s", args)
	}
}

func TestClientConfigRateAndShaping(t *testing.T) {
	config, err := ClientConfigFromEnv(env(map[string]string{"RIG_RATE_MBPS": "80"}))
	if err != nil || config.RateMBps != 80 {
		t.Fatalf("config = %+v, err = %v", config, err)
	}
	for _, bad := range []string{"0", "-1", "80M", "fast", "100001"} {
		if _, err := ClientConfigFromEnv(env(map[string]string{"RIG_RATE_MBPS": bad})); err == nil {
			t.Errorf("accepted RIG_RATE_MBPS=%q", bad)
		}
	}
	var lines []string
	for _, args := range ShapeCommands("eth0", 80) {
		lines = append(lines, strings.Join(args, " "))
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"tc qdisc replace dev eth0 root tbf rate 640mbit burst 1mbit latency 50ms",
		"tc filter add dev eth0 parent ffff: matchall action mirred egress redirect dev " + ifbDevice,
		"tc qdisc replace dev " + ifbDevice + " root tbf rate 640mbit burst 1mbit latency 50ms",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("shape commands lack %q:\n%s", want, got)
		}
	}
	args := withLinkMeta([]string{"--target-meta", "local:storage=x", "--target-meta", "nfs-async:server=k"},
		LinkCheck{RateMBps: 80, ReadMBps: 79.5, WriteMBps: 78.25})
	if args[1] != "local:storage=x" || args[3] != "nfs-async:server=k,rate_mbps=80,link_read_mbps=79.5,link_write_mbps=78.2" {
		t.Errorf("link meta = %v", args)
	}
}

func TestTargetArgsPutLocalFirstAndRecordTheServer(t *testing.T) {
	markers := map[string]ServerMarker{}
	for _, export := range Exports() {
		markers[export.Target] = ServerMarker{Kind: ServerKind, Kernel: "7.1", Export: export, Config: ServerConfig{Threads: 8}, BackingFS: "ext4"}
	}
	mount, _ := MountConfigFromEnv(env(nil))
	args := TargetArgs(markers, mount, "ext4")
	got := strings.Join(args, " ")
	for _, want := range []string{
		"--target local=/w --target-meta local:storage=container-volume,backing_fs=ext4 ",
		"--target nfs-async=/na --target-meta nfs-async:server=kernel-nfsd,export=async,",
		"--target nfs-sync=/ns --target-meta nfs-sync:server=kernel-nfsd,export=sync,",
		"localio=off,requested=vers=4.1;proto=tcp;hard;rsize=1048576;wsize=1048576",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("target args missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, "--target local=") {
		t.Errorf("local is not the first target: %s", got)
	}
}

func TestHostCommands(t *testing.T) {
	options := HostOptions{Context: "desktop-linux", Compose: "c.yaml", Source: "s", Results: "r", Label: "run1",
		Env: []string{"NFS_VERS=4.2", "NFS_ACTIMEO=0"}, SuiteArgs: []string{"--profile", "full"}}
	if err := options.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(options.UpArgs(), " "); !strings.HasPrefix(got, "--context desktop-linux compose -p rarpar-nfs -f /") || !strings.HasSuffix(got, "up -d --build --wait nfs-server") {
		t.Errorf("up = %s", got)
	}
	run := strings.Join(options.RunArgs(), " ")
	if !strings.HasSuffix(run, "run --rm --build -e NFS_ACTIMEO=0 -e NFS_VERS=4.2 bench-client nfs client -- --out /results/run1 --profile full") {
		t.Errorf("run = %s", run)
	}
	if got := strings.Join(options.DownArgs(true), " "); !strings.HasSuffix(got, "down --volumes") {
		t.Errorf("down = %s", got)
	}
	for _, bad := range []HostOptions{
		{Compose: "c", Source: "s", Results: "r", Label: "a/b"},
		{Compose: "c", Source: "s", Results: "r", Label: "a", Service: "other"},
		{Compose: "c", Source: "s", Label: "a"},
		{Compose: "c", Source: "s", Results: "r", Label: "a", Env: []string{"NOEQUALS"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
