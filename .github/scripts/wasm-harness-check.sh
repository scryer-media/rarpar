#!/usr/bin/env bash
#
# Non-vacuous gate + canonicaliser for the rarpar wasm correctness harnesses.
#
#   usage: wasm-harness-check.sh <par2|unrar> <report-file> <canon-out-file>
#
# The harnesses (`crates/weaver-par2/examples/wasm_par2_check.rs`,
# `crates/weaver-unrar/examples/wasm_extract_check.rs`) already exit non-zero
# when a case fails. That alone is a weak CI gate: a harness that silently ran
# *zero* cases — wrong fixture root, unhydrated LFS pointers, a case list
# accidentally filtered by `WEAVER_WASM_CASES`, a lane that never got built —
# also exits zero. So this script asserts the *presence* of every specific case
# row by its literal label, and asserts the properties that make each row
# load-bearing:
#
#   * every reconstruction row reports `miss>0`, i.e. Reed-Solomon
#     reconstruction genuinely ran instead of decaying into slice relocation
#     (this class of case is what caught a wasm trap-class repair bug);
#   * every I/O row reports an exact whole-file fill (the short-read/64 KiB-cap
#     regression class);
#   * every create row carries a 16-hex-digit digest;
#   * the harness's own totals line matches the expected case count exactly.
#
# It then writes the report's *canonical* form: the lane-invariant subset, in a
# fixed order, with the two genuinely host-dependent facts removed (the `lane=`
# header, and the informational "host single read=" cap that legitimately
# differs between `wasm32-wasip1` and `wasm32-wasip1-threads`). The caller
# diffs a wasm lane's canonical form against the *native* run captured in the
# same job, so digests are compared against a same-commit, same-fixture
# reference rather than a hardcoded constant that fixture churn would rot.
#
# MAINTENANCE: the label lists and the expected totals below are deliberately
# hardcoded, and adding a case to a harness will fail this script until the
# corresponding list is updated. That is the point — a gate that derives its
# expectations from the output it is checking cannot detect missing output.

set -euo pipefail

die() {
	printf '::error::%s\n' "$*" >&2
	exit 1
}

[ "$#" -eq 3 ] || die "usage: $0 <par2|unrar> <report-file> <canon-out-file>"

harness="$1"
report="$2"
canon_out="$3"

[ -s "$report" ] || die "$harness: report '$report' is missing or empty"

# Collapse runs of whitespace so the harnesses' column padding (and the labels'
# own internal alignment spaces) cannot make a literal match brittle.
norm() { sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ *$//'; }

normalized="$(norm <"$report")"

# Both harnesses open their report with a `lane=` header. Its presence is the
# cheapest proof that we are looking at a real report and not, say, a truncated
# log; its value tells us whether this run was the native reference or a wasm
# lane, which a couple of assertions below legitimately differ on.
lane_line="$(printf '%s\n' "$normalized" | grep -m1 '^lane=' || true)"
[ -n "$lane_line" ] ||
	die "$harness: report has no 'lane=' header line; this is not a harness report"
case "$lane_line" in
"lane=native" | "lane=native "*) lane_kind=native ;;
"lane=wasm32 "*) lane_kind=wasm ;;
*) die "$harness: unrecognised lane header '$lane_line'" ;;
esac

# The single row whose text begins with $1. `index(...) == 1` anchors at the
# start of the line without needing to regex-escape the labels' parentheses.
row_for() {
	printf '%s\n' "$normalized" | awk -v key="$1" 'index($0, key) == 1'
}

# Fetch exactly one row, or fail loudly naming the label that went missing.
require_row() {
	local key="$1" row count
	row="$(row_for "$key")"
	count="$(printf '%s' "$row" | grep -c . || true)"
	[ "$count" = "1" ] ||
		die "$harness: expected exactly 1 report row starting '$key', found $count"
	printf '%s\n' "$row"
}

require_tail() {
	printf '%s\n' "$normalized" | grep -qxF -- "$1" ||
		die "$harness: report is missing the exact totals line '$1'"
}

canon=""
emit() { canon="${canon}$1"$'\n'; }

case "$harness" in
par2)
	# Repair/verify cases. `reconstruct` rows are the miss>0 (Reed-Solomon
	# reconstruction) coverage; the others cover the relocation path.
	relocate_cases=(
		"rar5 lz plain (single-region)"
		"rar4 store enc (single-region)"
		"rar5 heavy damage (28 regions)"
	)
	reconstruct_cases=(
		"rar5 lz plain reconstruct"
		"rar4 store enc reconstruct"
		"rar5 heavy damage reconstruct"
	)
	io_cases=(
		"io fill rar5 lz plain (192KiB)"
		"io fill rar4 store enc"
	)
	create_cases=(
		"create rar5 lz plain (6 inputs)"
		"create rar5 heavy (73MiB)"
	)
	require_tail "cases=10 failed=0"
	canon_totals="cases=10 failed=0"

	for label in "${relocate_cases[@]}" "${reconstruct_cases[@]}"; do
		row="$(require_row "$label |")"
		# Healthy verify, damaged verify and the byte-exact repair are three
		# separate PASS/FAIL cells; the repair cell carries the digest.
		case "$row" in
		*"| PASS [Verified] | PASS ["*"] | PASS d="*) ;;
		*) die "$harness: case '$label' is not a full PASS row: $row" ;;
		esac
		printf '%s\n' "$row" | grep -qE '\| PASS d=[0-9a-f]{16}$' ||
			die "$harness: case '$label' has no 16-hex repair digest: $row"
		emit "$row"
	done

	# The reconstruction cases exist to force Reed-Solomon reconstruction. If a
	# pristine copy ever leaks back into the scanned directory the repairer
	# relocates the slices instead, the row still says PASS, and the coverage
	# quietly evaporates. miss>0 is the property that cannot be faked.
	for label in "${reconstruct_cases[@]}"; do
		row="$(row_for "$label |")"
		miss="$(printf '%s\n' "$row" | sed -n 's/.*[^a-z]miss=\([0-9][0-9]*\).*/\1/p')"
		[ -n "$miss" ] ||
			die "$harness: reconstruction case '$label' reports no miss= count: $row"
		[ "$miss" -gt 0 ] ||
			die "$harness: reconstruction case '$label' reports miss=$miss; it relocated slices instead of reconstructing them"
	done

	# Whole-file readback must fill exactly. The trailing "host single read="
	# cap is informational and legitimately differs per runtime, so it is
	# asserted to be present but dropped from the canonical form.
	for label in "${io_cases[@]}"; do
		row="$(require_row "$label |")"
		printf '%s\n' "$row" |
			grep -qE '\| PASS \| filled ([0-9]+)/\1; host single read=[0-9]+( \(CAPPED\))?$' ||
			die "$harness: I/O case '$label' is not an exact-fill PASS row: $row"
		emit "${row%%; host single read=*}"
	done

	for label in "${create_cases[@]}"; do
		row="$(require_row "$label |")"
		printf '%s\n' "$row" | grep -qE '\| PASS \| digest=[0-9a-f]{16}$' ||
			die "$harness: create case '$label' has no 16-hex digest: $row"
		emit "$row"
	done
	;;

unrar)
	# One row per fixture, in the harness's own order; the labels are its
	# literal `Case::label` strings with their alignment padding collapsed.
	extract_cases=(
		"rar5 store plain single"
		"rar5 lz plain single"
		"rar5 lz enc single"
		"rar5 store enc single"
		"rar5 lz plain SOLID"
		"rar5 store plain mv"
		"rar5 lz plain mv"
		"rar5 lz enc mv"
		"rar5 store enc mv"
		"rar4 store plain single"
		"rar4 lz plain single"
		"rar4 lz enc single"
		"rar4 store enc single"
		"rar4 lz plain SOLID"
		"rar4 ppmd plain SOLID"
		"rar4 store plain mv"
		"rar4 lz plain mv"
		"rar4 lz enc mv"
		"rar4 store enc mv"
		"rar4 lz plain SOLIDmv"
		"rar4 ppmd plain SOLIDmv"
	)

	for label in "${extract_cases[@]}"; do
		# The trailing " |" matters: it is what stops the key
		# "rar4 lz plain SOLID" from also matching the SOLIDmv row.
		row="$(require_row "PASS | $label |")"
		printf '%s\n' "$row" |
			grep -qE '\| [1-9][0-9]* members \| [0-9]+ bytes \| spill=[0-9]+ \| digest=[0-9a-f]{16}$' ||
			die "$harness: case '$label' is not a well-formed PASS row with >=1 member and a 16-hex digest: $row"
		# `spill=` is deliberately lane-dependent (see the totals check below),
		# so it is dropped from the canonical form; the member count, byte
		# count and digest — the actual cross-lane identity — are kept.
		emit "$(printf '%s\n' "$row" | sed 's/ spill=[0-9]* |/ |/')"
	done

	totals="$(require_row "passed=")"
	printf '%s\n' "$totals" |
		grep -qE "^passed=${#extract_cases[@]} failed=0 tempfile_spilled_members=[0-9]+$" ||
		die "$harness: totals line is not 'passed=${#extract_cases[@]} failed=0 tempfile_spilled_members=<n>': $totals"
	spilled="${totals##*=}"

	# The spool spills members above its threshold to a `NamedTempFile` on
	# native, and never on wasm: `ExtractedMemberSink::with_capacity_hint`
	# const-folds the spill decision away under
	# `!cfg!(target_family = "wasm")`, because WASI preview1's
	# `std::env::temp_dir()` is a `panic!` stub that does not consult $TMPDIR.
	# So the count is asserted per lane kind rather than compared across lanes:
	# native must exercise the spill path, wasm must stay in memory. A wasm run
	# that suddenly reports a spill means that platform assumption changed and
	# wants a human, not a silently-passing lane.
	case "$lane_kind" in
	native)
		[ "$spilled" -gt 0 ] ||
			die "$harness: native run reports tempfile_spilled_members=0; the NamedTempFile spill path never ran"
		;;
	wasm)
		[ "$spilled" -eq 0 ] ||
			die "$harness: wasm lane reports tempfile_spilled_members=$spilled, but WASI preview1 has no usable temp dir; the spool's wasm gate has changed"
		;;
	esac

	require_tail "$totals"
	canon_totals="${totals% tempfile_spilled_members=*}"
	;;

*)
	die "unknown harness '$harness' (expected 'par2' or 'unrar')"
	;;
esac

emit "$canon_totals"

printf '%s' "$canon" >"$canon_out"

printf '%s: %s report rows asserted, canonical form -> %s\n' \
	"$harness" "$(printf '%s' "$canon" | grep -c . || true)" "$canon_out"
