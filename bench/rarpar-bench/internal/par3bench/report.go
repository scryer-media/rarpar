package par3bench

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

// Stat is a median with its range.
type Stat struct {
	Median float64 `json:"median"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	N      int     `json:"n"`
}

func stat(values []float64) Stat {
	if len(values) == 0 {
		return Stat{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	median := sorted[middle]
	if len(sorted)%2 == 0 {
		median = (sorted[middle-1] + sorted[middle]) / 2
	}
	return Stat{Median: median, Min: sorted[0], Max: sorted[len(sorted)-1], N: len(sorted)}
}

// Row is one variant's summary for one configuration and operation.
type Row struct {
	Config  string
	Op      string
	Variant string
	Tool    string
	// DNF describes why a reference row did not finish; empty otherwise.
	DNF      string
	Wall     Stat
	CPU      Stat
	RSS      Stat
	BlockIn  Stat
	BlockOut Stat
	ReadOps  Stat
	WriteOps Stat
	// Target is the storage target; Load the harness machine's 1-minute
	// load average before each run.
	Target string
	Load   Stat
	// Engine counters (engine rows) and NFS client counters (NFS targets),
	// medians over the measured runs; HasEngine / HasNFS say whether any
	// run carried them.
	HasEngine                                            bool
	EngineReadBytes, EngineReadCalls                     Stat
	EngineWriteBytes, EngineWriteCalls                   Stat
	EngineOpens, EngineSyncs, EngineSyncSeconds          Stat
	EngineClones                                         Stat
	HasNFS                                               bool
	NFSRead, NFSWrite, NFSCommit, NFSMeta, NFSAll        Stat
	NFSServerReadBytes, NFSServerWriteBytes, NFSReadRTTs Stat
	Failed                                               int
	Identity                                             string
	Repaired                                             string
	Extra                                                string
	// Backup is the row's Variant.Backup; LeftBackup says whether its
	// measured repairs kept a numbered backup of a repaired file ("true",
	// "false", or "false/true" when they disagreed; "" without one).
	Backup     bool
	LeftBackup string
}

// Summarize groups measured (non-warmup) runs into rows, in variant order.
func Summarize(results *Results) []Row {
	type key struct{ config, op, variant string }
	grouped := map[key][]RunRecord{}
	dnf := map[key]RunRecord{}
	for _, run := range results.Runs {
		k := key{run.Config, run.Op, run.Variant}
		if run.Status == StatusDNF {
			// A DNF ends the row whether it hit a warmup, a measured run,
			// or the canonical seed.
			if _, seen := dnf[k]; !seen {
				dnf[k] = run
			}
			continue
		}
		if run.Warmup {
			continue
		}
		grouped[k] = append(grouped[k], run)
	}
	var rows []Row
	for _, config := range results.Configs {
		for _, op := range results.Ops {
			for _, variant := range results.Variants {
				k := key{config.ID, op, variant.Name}
				runs := grouped[k]
				stopped, didNotFinish := dnf[k]
				if len(runs) == 0 && !didNotFinish {
					continue
				}
				row := Row{Config: config.ID, Op: op, Variant: variant.Name, Tool: variant.Tool, Target: variant.Target, Backup: variant.Backup}
				if didNotFinish {
					row.DNF = describeDNF(stopped)
				}
				var wall, cpu, rss, bin, bout, rops, wops, load []float64
				engine := make([][]float64, 8)
				nfs := make([][]float64, 8)
				identities := map[string]bool{}
				repaired := map[string]bool{}
				extras := map[string]bool{}
				kept := map[string]bool{}
				for _, run := range runs {
					if run.Status != StatusOK {
						row.Failed++
						continue
					}
					wall = append(wall, run.WallSeconds)
					cpu = append(cpu, run.UserSeconds+run.SysSeconds)
					rss = append(rss, float64(run.MaxRSSBytes))
					bin = append(bin, float64(run.BlockInOps))
					bout = append(bout, float64(run.BlockOutOps))
					rops = append(rops, float64(run.ReadOps))
					wops = append(wops, float64(run.WriteOps))
					load = append(load, run.LoadAverage)
					if e := run.Engine; e != nil {
						row.HasEngine = true
						for i, value := range []float64{float64(e.ReadBytes), float64(e.ReadCalls), float64(e.WriteBytes),
							float64(e.WriteCalls), float64(e.Opens), float64(e.Syncs), e.SyncSeconds, float64(e.Clones)} {
							engine[i] = append(engine[i], value)
						}
					}
					if n := run.NFS; n != nil {
						row.HasNFS = true
						for i, value := range []int64{n.Op("READ"), n.Op("WRITE"), n.Op("COMMIT"), n.MetadataOps(), n.TotalOps(),
							n.ServerReadBytes, n.ServerWriteBytes, n.Ops["READ"].RTTMS} {
							nfs[i] = append(nfs[i], float64(value))
						}
					}
					if run.Identity != nil {
						identities[run.Identity.Verdict()] = true
					}
					if run.Repair != nil {
						repaired[fmt.Sprint(run.Repair.Match)] = true
						for _, extra := range run.Repair.ExtraFiles {
							extras[extra] = true
						}
						kept[fmt.Sprint(len(run.Repair.Backups) > 0)] = true
					}
				}
				row.Wall, row.CPU, row.RSS = stat(wall), stat(cpu), stat(rss)
				row.BlockIn, row.BlockOut, row.ReadOps, row.WriteOps = stat(bin), stat(bout), stat(rops), stat(wops)
				row.Load = stat(load)
				row.EngineReadBytes, row.EngineReadCalls, row.EngineWriteBytes = stat(engine[0]), stat(engine[1]), stat(engine[2])
				row.EngineWriteCalls, row.EngineOpens, row.EngineSyncs, row.EngineSyncSeconds = stat(engine[3]), stat(engine[4]), stat(engine[5]), stat(engine[6])
				row.EngineClones = stat(engine[7])
				row.NFSRead, row.NFSWrite, row.NFSCommit, row.NFSMeta = stat(nfs[0]), stat(nfs[1]), stat(nfs[2]), stat(nfs[3])
				row.NFSAll, row.NFSServerReadBytes, row.NFSServerWriteBytes, row.NFSReadRTTs = stat(nfs[4]), stat(nfs[5]), stat(nfs[6]), stat(nfs[7])
				row.Identity = strings.Join(sortedKeys(identities), "/")
				row.Repaired = strings.Join(sortedKeys(repaired), "/")
				row.Extra = strings.Join(sortedKeys(extras), " ")
				row.LeftBackup = strings.Join(sortedKeys(kept), "/")
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func seconds(s Stat) string {
	if s.N == 0 {
		return "-"
	}
	return fmt.Sprintf("%.3f [%.3f–%.3f]", s.Median, s.Min, s.Max)
}

func mebibytes(s Stat) string {
	if s.N == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f [%.0f–%.0f]", s.Median/(1<<20), s.Min/(1<<20), s.Max/(1<<20))
}

func count(s Stat) string {
	if s.N == 0 {
		return "-"
	}
	if s.Min == s.Max {
		return fmt.Sprintf("%.0f", s.Median)
	}
	return fmt.Sprintf("%.0f [%.0f–%.0f]", s.Median, s.Min, s.Max)
}

func ratio(ours, reference Stat) string {
	if ours.N == 0 || reference.N == 0 || reference.Median == 0 {
		return "-"
	}
	if ours.Median == 0 {
		return "-"
	}
	return fmt.Sprintf("%.3f", reference.Median/ours.Median)
}

// RenderReport renders the Markdown report: one table per configuration and
// operation, medians with [min–max], and reference/ours ratios (above 1.000
// means rarpar was faster or used less).
func RenderReport(results *Results) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PAR3 benchmark: %s\n\n", results.Profile)
	fmt.Fprintf(&b, "- Host: %s, %s/%s, %d logical CPUs\n", results.Machine.CPU, results.Machine.OS, results.Machine.Architecture, results.Machine.CPUCount)
	fmt.Fprintf(&b, "- Reference: %s (sha256 %s)\n", results.Reference.Version, short(results.Reference.SHA256))
	fmt.Fprintf(&b, "- Candidate: %s (sha256 %s)\n", results.Candidate.Version, short(results.Candidate.SHA256))
	fmt.Fprintf(&b, "- Protocol: %d warmup + %d measured runs per variant, order alternated each repeat; workers %v", results.Warmups, results.Repeats, results.Workers)
	if results.PinCPUs != "" {
		fmt.Fprintf(&b, "; pinned to CPUs %s (applied: %t)", results.PinCPUs, results.PinApplied)
	}
	fmt.Fprintln(&b)
	carrierSets := hasCarrierSet(results)
	if carrierSets {
		fmt.Fprint(&b, "- Output: every rarpar row on a plain set runs buffered and the bench never passes `--fsync`; durability is the caller's concern, not PAR3's. The reference never syncs.")
	} else {
		fmt.Fprint(&b, "- Output: every rarpar row runs buffered and the bench never passes `--fsync`; durability is the caller's concern, not PAR3's. The reference never syncs.")
	}
	if summary := bufferedSummary(results.Ops, results.BufferedArgs, results.BufferedUnsupported); summary != "" {
		fmt.Fprint(&b, " "+summary)
	}
	if carrierSets {
		fmt.Fprint(&b, " On a PAR-inside set rarpar runs its par3cmdline-compatible front end (`vs`/`rs`) instead, which has no buffered mode: its repair syncs the rebuilt carrier, so those repair rows are not buffered.")
	}
	fmt.Fprintln(&b)
	if contains(results.Ops, OpRepair) {
		fmt.Fprint(&b, "- Repair rows: the reference keeps a numbered `.1` backup of every file it repairs. Each `rarpar-wN-backup` row does the same, so the `-backup` rows are the rarpar rows that are like for like with the reference on bytes written; each `rarpar-wN` row (and every kernel row) repairs in place and keeps no backup, the candidate's default. A rarpar repair on a plain set whose backups contradict its row (a `-backup` row that kept none, an in-place row that kept one) fails as `backup-mismatch`.")
		if summary := backupSummary(results); summary != "" {
			fmt.Fprint(&b, " "+summary)
		}
		if carrierSets {
			fmt.Fprint(&b, " A PAR-inside set has one rarpar row, through the compatible `rs`, which keeps the damaged carrier as a numbered `.1` as the reference does: like for like on bytes written.")
		}
		fmt.Fprintln(&b)
	}
	if results.TimeoutSeconds > 0 {
		fmt.Fprintf(&b, "- Per-run timeout %s (reference %s); a reference run that exits non-zero, is killed, times out, or writes missing, unreadable or truncated carriers is **DNF** and the rest of the matrix still runs\n",
			formatTimeout(results.TimeoutSeconds), formatTimeout(results.ReferenceTimeoutSeconds))
	}
	if len(results.Rows) > 0 {
		fmt.Fprintf(&b, "- Row kinds: %s", strings.Join(results.Rows, ", "))
		if len(results.EngineWorkers) > 0 {
			fmt.Fprintf(&b, "; engine rows (par3-rs engine_perf, not the shipped CLI, no ratios) at workers %v", results.EngineWorkers)
		}
		fmt.Fprintln(&b)
	}
	if results.DropCaches {
		fmt.Fprintln(&b, "- Page cache dropped before every timed run (cold reads)")
	}
	for _, target := range results.Targets {
		name := target.Target
		if name == "" {
			name = "work"
		}
		fmt.Fprintf(&b, "- Target `%s`: %s", name, target.StorageLabel())
		if target.MountPoint != "" {
			fmt.Fprintf(&b, "; mount %s from %s (%s)", target.MountPoint, target.Source, target.MountOptions)
		}
		if target.NFSOptions != "" {
			fmt.Fprintf(&b, "; NFS client options `%s`", target.NFSOptions)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, "- Started %s, finished %s, status **%s**\n\n", results.StartedUTC, results.FinishedUTC, results.Status)
	fmt.Fprintln(&b, "Wall and CPU (user+sys) are seconds, RSS is peak MiB; cells are median [min–max]. Every ratio is reference/rarpar medians: above 1.000 rarpar was faster or used less. The reference is single-threaded. Every rarpar row is compared with the same reference row.")
	fmt.Fprintln(&b, "Carriers: `identical` = byte-identical to the reference's set; `payloads-only` = every recovery block's payload matches but packet metadata differs; `DIFFERENT` = recovery payloads differ.")
	fmt.Fprintln(&b)
	procmeasure.RenderRSSSummary(&b, RSSSummary(results))

	windowsCounters := false
	for _, run := range results.Runs {
		if run.ReadOps > 0 || run.WriteOps > 0 {
			windowsCounters = true
			break
		}
	}
	rows := Summarize(results)
	references := map[string]Row{}
	for _, row := range rows {
		if row.Tool == ToolReference {
			references[row.Config+"/"+row.Op+"@"+row.Target] = row
		}
	}
	configs := map[string]ConfigSummary{}
	for _, config := range results.Configs {
		configs[config.ID] = config
	}
	current := ""
	for _, row := range rows {
		group := row.Config + "/" + row.Op
		if group != current {
			current = group
			config := configs[row.Config]
			fmt.Fprintf(&b, "## %s — %s\n\n", row.Config, row.Op)
			fmt.Fprintf(&b, "%s; %d input blocks of %d bytes, %d recovery, codec %s", config.Note, config.InputBlocks, config.BlockSize, config.Recovery, config.Codec)
			if config.Codec == "fft" {
				fmt.Fprintf(&b, " (capacity 2^%d)", config.CapacityLog2)
			}
			if row.Op == OpRepair || row.Op == OpVerifyDamaged {
				fmt.Fprintf(&b, "; damage %s (%d blocks)", config.Damage.Name, config.Damage.LostBlocks())
			}
			fmt.Fprint(&b, ".\n\n")
			if row.Op == OpRepair {
				if line := likeForLikeLine(rows, row.Config, config.Carrier != ""); line != "" {
					fmt.Fprintf(&b, "%s\n\n", line)
				}
			}
			header := "| variant | wall s | CPU s | RSS MiB | wall ratio | CPU ratio | RSS ratio |"
			rule := "|---|---|---|---|---|---|---|"
			if windowsCounters {
				header += " read ops | write ops |"
				rule += "---|---|"
			} else {
				header += " blk in | blk out |"
				rule += "---|---|"
			}
			switch row.Op {
			case OpCreate:
				header += " carriers |"
				rule += "---|"
			case OpRepair:
				header += " repaired | left behind |"
				rule += "---|---|"
			}
			header += " failed |"
			rule += "---|"
			fmt.Fprintln(&b, header)
			fmt.Fprintln(&b, rule)
		}
		reference, hasReference := references[group+"@"+row.Target]
		line := fmt.Sprintf("| %s |", row.Variant)
		switch {
		case row.DNF != "":
			line += " DNF | - | - | - | - | - |"
		case row.Tool == ToolReference:
			self := "1.000"
			if row.Wall.N == 0 {
				// Every reference run failed: there is nothing to be 1.000 of.
				self = "-"
			}
			line += fmt.Sprintf(" %s | %s | %s | %s | %s | %s |", seconds(row.Wall), seconds(row.CPU), mebibytes(row.RSS), self, self, self)
		case row.Tool == ToolEngine || !hasReference:
			line += fmt.Sprintf(" %s | %s | %s | - | - | - |", seconds(row.Wall), seconds(row.CPU), mebibytes(row.RSS))
		case reference.DNF != "":
			line += fmt.Sprintf(" %s | %s | %s | - | - | - |", seconds(row.Wall), seconds(row.CPU), mebibytes(row.RSS))
		default:
			line += fmt.Sprintf(" %s | %s | %s | %s | %s | %s |", seconds(row.Wall), seconds(row.CPU), mebibytes(row.RSS),
				ratio(row.Wall, reference.Wall), ratio(row.CPU, reference.CPU), ratio(row.RSS, reference.RSS))
		}
		if windowsCounters {
			line += fmt.Sprintf(" %s | %s |", count(row.ReadOps), count(row.WriteOps))
		} else {
			line += fmt.Sprintf(" %s | %s |", count(row.BlockIn), count(row.BlockOut))
		}
		switch row.Op {
		case OpCreate:
			line += fmt.Sprintf(" %s |", orDash(row.Identity))
		case OpRepair:
			line += fmt.Sprintf(" %s | %s |", orDash(row.Repaired), orDash(row.Extra))
		}
		line += fmt.Sprintf(" %d |", row.Failed)
		fmt.Fprintln(&b, line)
		// Close the table after the group's last row.
		if next := nextGroup(rows, row); next != group {
			fmt.Fprintln(&b)
			writeDNFDetail(&b, rows, group, configs[row.Config])
			writeIdentityDetail(&b, results, row.Config, row.Op)
			writeIOCounts(&b, results, row.Config, row.Op)
			writeDiskWork(&b, rows, group)
		}
	}
	if len(results.EnginePerfRuns) > 0 {
		fmt.Fprintln(&b, "## engine_perf stage breakdown (untimed pass)")
		fmt.Fprintln(&b)
		for _, run := range results.EnginePerfRuns {
			fmt.Fprintf(&b, "- %s %s w%d: %.3fs", run.Config, run.Op, run.Workers, run.WallSeconds)
			if run.Error != "" {
				fmt.Fprintf(&b, " — error: %s", run.Error)
			}
			fmt.Fprintln(&b)
			for _, line := range run.Lines {
				fmt.Fprintf(&b, "  - `%s`\n", string(line))
			}
		}
		fmt.Fprintln(&b)
	}
	if len(results.Notes) > 0 || len(results.Failures) > 0 || len(results.DNF) > 0 {
		fmt.Fprintln(&b, "## Notes")
		fmt.Fprintln(&b)
		for _, dnf := range results.DNF {
			fmt.Fprintf(&b, "- %s\n", dnf)
		}
		for _, note := range results.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		for _, failure := range results.Failures {
			fmt.Fprintf(&b, "- FAILURE: %s\n", failure)
		}
	}
	return b.String()
}

// bufferedSummary says, per writing op in ops, how its rarpar rows ran
// buffered on this candidate (see Results.BufferedArgs), or "" when no
// writing op was probed.
func bufferedSummary(ops []string, args map[string][]string, unsupported []string) string {
	var parts []string
	for _, op := range []string{OpCreate, OpRepair} {
		if !contains(ops, op) {
			continue
		}
		selected, probed := args[op]
		switch {
		case contains(unsupported, op):
			parts = append(parts, fmt.Sprintf("`rarpar par3 %s` on this candidate has no buffered mode and runs the plain command", op))
		case !probed:
			continue
		case len(selected) == 0:
			parts = append(parts, fmt.Sprintf("`rarpar par3 %s` is buffered when run plain", op))
		default:
			parts = append(parts, fmt.Sprintf("`rarpar par3 %s` runs with `%s`", op, strings.Join(selected, " ")))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ") + "."
}

// describeArgs is how a row's probed arguments read in a sentence.
func describeArgs(args []string) string {
	if len(args) == 0 {
		return "plain"
	}
	return "with `" + strings.Join(args, " ") + "`"
}

// backupSummary says how the rarpar repair rows selected their backup mode
// on this candidate (see Results.BackupArgs), or "" when repair was not
// probed.
func backupSummary(results *Results) string {
	if results.BackupArgs == nil {
		return ""
	}
	var inPlace, backup []string
	var haveInPlace, haveBackup bool
	for _, variant := range results.Variants {
		args, probed := results.BackupArgs[variant.Name]
		switch {
		case !probed:
		case variant.Backup && !haveBackup:
			backup, haveBackup = args, true
		case !variant.Backup && !haveInPlace:
			inPlace, haveInPlace = args, true
		}
	}
	switch {
	case results.InPlaceUnsupported && haveBackup:
		return "This candidate's `par3 repair --help` lists neither --backup nor --no-backup, so it cannot be told to repair in place: only the `-backup` rows ran repair, " + describeArgs(backup) + "."
	case haveInPlace && haveBackup:
		return "On this candidate the in-place rows run " + describeArgs(inPlace) + " and the `-backup` rows " + describeArgs(backup) + "."
	}
	return ""
}

// likeForLikeLine names, under a repair table, the rarpar rows that are like
// for like with the reference on bytes written: the `-backup` rows on a plain
// set, and on a PAR-inside set the compatible `rs` row when its repairs kept
// the damaged carrier as a numbered backup.
func likeForLikeLine(rows []Row, config string, carrier bool) string {
	var like, other []string
	for _, row := range rows {
		if row.Config != config || row.Op != OpRepair || row.Tool != ToolCandidate {
			continue
		}
		if carrier {
			if row.LeftBackup == "true" {
				return fmt.Sprintf("Like for like with the reference on bytes written: `%s`, which runs the compatible `rs` and keeps the damaged carrier as a numbered backup, as the reference does.", row.Variant)
			}
			if row.LeftBackup != "" {
				return fmt.Sprintf("`%s` runs the compatible `rs` but did not keep the damaged carrier as a numbered backup in every run (see left behind), so it is not like for like with the reference on bytes written.", row.Variant)
			}
			continue
		}
		if row.Backup {
			like = append(like, "`"+row.Variant+"`")
		} else {
			other = append(other, "`"+row.Variant+"`")
		}
	}
	if len(like) == 0 {
		return ""
	}
	line := "Like for like with the reference on bytes written: " + strings.Join(like, ", ") +
		plural(len(like), ", which keeps a numbered `.1` backup of every file it repairs", ", which keep a numbered `.1` backup of every file they repair") +
		", as the reference does."
	if len(other) > 0 {
		line += " " + strings.Join(other, ", ") + plural(len(other), " repairs in place and writes no backup.", " repair in place and write no backup.")
	}
	return line
}

// plural picks the singular or plural form for n subjects.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// hasCarrierSet reports whether any configuration is a PAR-inside set.
func hasCarrierSet(results *Results) bool {
	for _, config := range results.Configs {
		if config.Carrier != "" {
			return true
		}
	}
	return false
}

func formatTimeout(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).String()
}

func writeDNFDetail(b *strings.Builder, rows []Row, group string, config ConfigSummary) {
	wrote := false
	for _, row := range rows {
		if row.Config+"/"+row.Op != group || row.DNF == "" {
			continue
		}
		fmt.Fprintf(b, "- %s DNF: %s\n", row.Variant, row.DNF)
		wrote = true
	}
	if config.CanonicalSource == ToolCandidate && strings.HasSuffix(group, "/"+OpCreate) {
		fmt.Fprintln(b, "- The reference did not finish the canonical create, so rarpar's carriers were used for verify and repair; no identity verdict exists for this set.")
		wrote = true
	}
	if wrote {
		fmt.Fprintln(b)
	}
}

func nextGroup(rows []Row, current Row) string {
	for i := range rows {
		if rows[i].Config == current.Config && rows[i].Op == current.Op && rows[i].Variant == current.Variant {
			if i+1 < len(rows) {
				return rows[i+1].Config + "/" + rows[i+1].Op
			}
			return ""
		}
	}
	return ""
}

func writeIdentityDetail(b *strings.Builder, results *Results, config, op string) {
	if op != OpCreate {
		return
	}
	seen := map[string]bool{}
	for _, run := range results.Runs {
		if run.Config != config || run.Op != op || run.Tool != ToolCandidate || run.Identity == nil || run.Identity.Bytes || seen[run.Variant] {
			continue
		}
		seen[run.Variant] = true
		identity := run.Identity
		fmt.Fprintf(b, "- %s carriers differ from the reference: same layout %t, same InputSetID %t, recovery payloads %d/%d equal",
			run.Variant, identity.Layout, identity.SameInputSetID, identity.RecoveryMatched, identity.RecoveryTotal)
		if strings.Join(identity.ReferenceFields, ",") != strings.Join(identity.CandidateFields, ",") {
			fmt.Fprintf(b, "; Galois field rarpar=%s reference=%s", strings.Join(identity.CandidateFields, ","), strings.Join(identity.ReferenceFields, ","))
		}
		if len(identity.DifferingTypes) > 0 {
			fmt.Fprintf(b, "; differing packet types: %s", strings.Join(identity.DifferingTypes, ", "))
		}
		if len(identity.CountDifferences) > 0 {
			shown := identity.CountDifferences
			if len(shown) > 4 {
				shown = append(shown[:4:4], fmt.Sprintf("… %d more", len(identity.CountDifferences)-4))
			}
			fmt.Fprintf(b, "; packet counts: %s", strings.Join(shown, ", "))
		}
		if strings.Join(identity.ReferenceCreator, "") != strings.Join(identity.CandidateCreator, "") {
			fmt.Fprintf(b, "; Creator %q vs %q", strings.Join(identity.CandidateCreator, ""), strings.Join(identity.ReferenceCreator, ""))
		}
		fmt.Fprintln(b)
	}
	if len(seen) > 0 {
		fmt.Fprintln(b)
	}
}

func writeIOCounts(b *strings.Builder, results *Results, config, op string) {
	var records []IOCountRecord
	for _, record := range results.IOCounts {
		if record.Config == config && record.Op == op {
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		return
	}
	fmt.Fprintln(b, "Syscall counts (untimed strace pass):")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| variant | reads | writes | opens | stats | seeks | syncs | all syscalls |")
	fmt.Fprintln(b, "|---|---|---|---|---|---|---|---|")
	for _, record := range records {
		if record.Error != "" {
			fmt.Fprintf(b, "| %s | error: %s |||||||\n", record.Variant, record.Error)
			continue
		}
		c := record.Counts
		fmt.Fprintf(b, "| %s | %d | %d | %d | %d | %d | %d | %d |\n", record.Variant, c.Reads, c.Writes, c.Opens, c.Stats, c.Seeks, c.Syncs, c.Total)
	}
	fmt.Fprintln(b)
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func short(digest string) string {
	if len(digest) > 16 {
		return digest[:16]
	}
	return digest
}

// writeDiskWork tabulates the engine's disk-work counters and the NFS
// client's operation counts for one configuration and operation, when any
// row carried them.
func writeDiskWork(b *strings.Builder, rows []Row, group string) {
	var selected []Row
	for _, row := range rows {
		if row.Config+"/"+row.Op == group && (row.HasEngine || row.HasNFS) {
			selected = append(selected, row)
		}
	}
	if len(selected) == 0 {
		return
	}
	fmt.Fprintln(b, "Disk work per run (medians [min–max]). Engine: par3-rs ExecutionDiagnostics (engine rows only; clones are reflink copies, which write no bytes). NFS: client mountstats deltas over the run (NFS targets only); meta = every op but READ/WRITE/COMMIT; wire MiB = bytes the client read from / wrote to the server. Load = 1-minute load average before the run.")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| variant | eng read MiB | eng reads | eng write MiB | eng writes | clones | opens | fsyncs | fsync s | NFS READ | NFS WRITE | NFS COMMIT | NFS meta | NFS ops | wire read MiB | wire write MiB | load |")
	fmt.Fprintln(b, "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
	for _, row := range selected {
		engine := "| - | - | - | - | - | - | - | - |"
		if row.HasEngine {
			engine = fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |", mebibytes(row.EngineReadBytes), count(row.EngineReadCalls),
				mebibytes(row.EngineWriteBytes), count(row.EngineWriteCalls), count(row.EngineClones), count(row.EngineOpens), count(row.EngineSyncs),
				seconds(row.EngineSyncSeconds))
		}
		nfs := " - | - | - | - | - | - | - |"
		if row.HasNFS {
			nfs = fmt.Sprintf(" %s | %s | %s | %s | %s | %s | %s |", count(row.NFSRead), count(row.NFSWrite), count(row.NFSCommit),
				count(row.NFSMeta), count(row.NFSAll), mebibytes(row.NFSServerReadBytes), mebibytes(row.NFSServerWriteBytes))
		}
		fmt.Fprintf(b, "| %s %s%s %s |\n", row.Variant, engine, nfs, loadText(row.Load))
	}
	fmt.Fprintln(b)
}

func loadText(s Stat) string {
	if s.N == 0 || s.Max == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f [%.1f–%.1f]", s.Median, s.Min, s.Max)
}
