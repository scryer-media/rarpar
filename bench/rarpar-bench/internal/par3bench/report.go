package par3bench

import (
	"fmt"
	"sort"
	"strings"
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
	Config   string
	Op       string
	Variant  string
	Tool     string
	Wall     Stat
	CPU      Stat
	RSS      Stat
	BlockIn  Stat
	BlockOut Stat
	ReadOps  Stat
	WriteOps Stat
	Failed   int
	Identity string
	Repaired string
	Extra    string
}

// Summarize groups measured (non-warmup) runs into rows, in variant order.
func Summarize(results *Results) []Row {
	type key struct{ config, op, variant string }
	grouped := map[key][]RunRecord{}
	for _, run := range results.Runs {
		if run.Warmup {
			continue
		}
		k := key{run.Config, run.Op, run.Variant}
		grouped[k] = append(grouped[k], run)
	}
	var rows []Row
	for _, config := range results.Configs {
		for _, op := range results.Ops {
			for _, variant := range results.Variants {
				runs := grouped[key{config.ID, op, variant.Name}]
				if len(runs) == 0 {
					continue
				}
				row := Row{Config: config.ID, Op: op, Variant: variant.Name, Tool: variant.Tool}
				var wall, cpu, rss, bin, bout, rops, wops []float64
				identities := map[string]bool{}
				repaired := map[string]bool{}
				extras := map[string]bool{}
				for _, run := range runs {
					if run.Status != "ok" {
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
					if run.Identity != nil {
						identities[run.Identity.Verdict()] = true
					}
					if run.Repair != nil {
						repaired[fmt.Sprint(run.Repair.Match)] = true
						for _, extra := range run.Repair.ExtraFiles {
							extras[extra] = true
						}
					}
				}
				row.Wall, row.CPU, row.RSS = stat(wall), stat(cpu), stat(rss)
				row.BlockIn, row.BlockOut, row.ReadOps, row.WriteOps = stat(bin), stat(bout), stat(rops), stat(wops)
				row.Identity = strings.Join(sortedKeys(identities), "/")
				row.Repaired = strings.Join(sortedKeys(repaired), "/")
				row.Extra = strings.Join(sortedKeys(extras), " ")
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
	return fmt.Sprintf("%.3f", ours.Median/reference.Median)
}

// RenderReport renders the Markdown report: one table per configuration and
// operation, medians with [min–max], and ours/reference ratios (below 1.000
// means rarpar used less).
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
	fmt.Fprintf(&b, "\n- Started %s, finished %s, status **%s**\n\n", results.StartedUTC, results.FinishedUTC, results.Status)
	fmt.Fprintln(&b, "Wall and CPU (user+sys) are seconds, RSS is peak MiB; cells are median [min–max]. Ratios are rarpar/reference medians: below 1.000 rarpar used less. The reference is single-threaded.")
	fmt.Fprintln(&b, "Carriers: `identical` = byte-identical to the reference's set; `payloads-only` = every recovery block's payload matches but packet metadata differs; `DIFFERENT` = recovery payloads differ.")
	fmt.Fprintln(&b)

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
			references[row.Config+"/"+row.Op] = row
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
		reference := references[group]
		line := fmt.Sprintf("| %s | %s | %s | %s |", row.Variant, seconds(row.Wall), seconds(row.CPU), mebibytes(row.RSS))
		if row.Tool == ToolReference {
			line += " 1.000 | 1.000 | 1.000 |"
		} else {
			line += fmt.Sprintf(" %s | %s | %s |", ratio(row.Wall, reference.Wall), ratio(row.CPU, reference.CPU), ratio(row.RSS, reference.RSS))
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
			writeIdentityDetail(&b, results, row.Config, row.Op)
			writeIOCounts(&b, results, row.Config, row.Op)
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
	if len(results.Notes) > 0 || len(results.Failures) > 0 {
		fmt.Fprintln(&b, "## Notes")
		fmt.Fprintln(&b)
		for _, note := range results.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		for _, failure := range results.Failures {
			fmt.Fprintf(&b, "- FAILURE: %s\n", failure)
		}
	}
	return b.String()
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
