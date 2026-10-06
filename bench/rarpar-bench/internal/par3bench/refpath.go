package par3bench

import (
	"fmt"
	"path/filepath"
	"strconv"
)

// referenceNameBuffer is the size of the first buffer par3cmdline allocates
// for the list of recovery file names it will reopen later (_MAX_FNAME * 4,
// rounded up to 1 KiB). When the list outgrows it the buffer is reallocated,
// but pointers into the old buffer are still held for every volume written so
// far (libpar3/write.c keeps position_list[].name into par_file_name), so the
// later reopen fails with "Failed to open Recovery File". That path is taken
// when recovery blocks are computed after the volumes are laid out — the FFT
// codec, and Cauchy sets too large to hold in memory — so the total length of
// the absolute volume paths is what matters, not any single path.
// par3cmdline turns the output path into an absolute one first, so passing a
// relative path does not help; only a shorter work directory does.
const referenceNameBuffer = 1024

// ReferenceNameBytes is the space par3cmdline's name list needs for a create
// that writes stem "set" into dir with the given recovery count, using its
// default power-of-two volume scheme: the index file plus volumes
// vol0+1, vol1+2, vol3+4, ... with zero-padded start and count fields.
func ReferenceNameBytes(dir string, recovery int64) int {
	var starts, counts []int64
	var maxCount int64
	for start, size := int64(0), int64(1); start < recovery; size *= 2 {
		count := size
		if count > recovery-start {
			count = recovery - start
		}
		starts = append(starts, start)
		counts = append(counts, count)
		if count > maxCount {
			maxCount = count
		}
		start += count
	}
	prefix := len(dir) + 1 // dir + separator
	total := prefix + len("set.par3") + 1
	if len(starts) == 0 {
		return total
	}
	startDigits := len(strconv.FormatInt(starts[len(starts)-1], 10))
	countDigits := len(strconv.FormatInt(maxCount, 10))
	for range starts {
		total += prefix + len("set.vol") + startDigits + 1 + countDigits + len(".par3") + 1
	}
	return total
}

// referencePathWarnings lists every set whose reference output paths under
// work would overflow par3cmdline's name buffer. It is a warning, not a
// refusal: the run goes ahead, and a reference that then fails is recorded as
// DNF while the rarpar rows still run.
func referencePathWarnings(profile Profile, work string) []string {
	var warnings []string
	for _, config := range profile.Configs {
		worst := 0
		for _, dir := range []string{
			filepath.Join(work, "k", config.ID),
			filepath.Join(work, "s", config.ID, "create-ref"),
		} {
			if need := ReferenceNameBytes(dir, config.Recovery); need > worst {
				worst = need
			}
		}
		if worst < referenceNameBuffer {
			continue
		}
		excess := worst - referenceNameBuffer + 1
		volumes := volumeCount(config.Recovery)
		warnings = append(warnings, fmt.Sprintf("set %s: --work %s (%d characters) gives the reference %d characters of absolute file names for its %d recovery volumes; par3cmdline mishandles more than %d (a dangling pointer after its name list grows; it exits 6 with \"Failed to open Recovery File\"). Running anyway: if the reference fails, its rows for this set are recorded as DNF. Shortening --work by %d characters avoids the risk",
			config.ID, work, len(work), worst, volumes, referenceNameBuffer-1, shortenBy(excess, volumes+1)))
	}
	return warnings
}

func volumeCount(recovery int64) int {
	count := 0
	for start, size := int64(0), int64(1); start < recovery; size *= 2 {
		start += size
		count++
	}
	return count
}

// shortenBy spreads the excess over every name that carries the directory.
func shortenBy(excess, names int) int {
	return (excess + names - 1) / names
}

// WorkPathWarnings applies the same reference name-buffer check to a work
// directory chosen elsewhere (the fleet plan), before anything runs.
func WorkPathWarnings(profile Profile, work string) []string {
	return referencePathWarnings(profile, work)
}
