#!/usr/bin/env bash
# Measure production-line test coverage across workspace and qemu-sim,
# outputting target/coverage/summary.md and enforcing a coverage floor.
#
# Usage: scripts/coverage.sh
# Env:   COVERAGE_FLOOR  integer floor percentage (default: 93)
#        COV_OUT         output directory (default: target/coverage)
#        LLVM_BIN        directory containing llvm tools (default: auto-detected)
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.."

COVERAGE_FLOOR="${COVERAGE_FLOOR:-93}"
COV_OUT="${COV_OUT:-target/coverage}"

awk_version="$(awk --version 2>/dev/null | head -n1 || true)"
if [[ "$awk_version" != *"GNU Awk"* ]]; then
    echo "scripts/coverage.sh requires GNU awk (gawk)" >&2
    exit 1
fi

if [ -z "${LLVM_BIN:-}" ]; then
    llvm_major="$(rustc -vV | sed -n 's/^LLVM version: \([0-9]*\).*/\1/p')"
    if [ -n "$llvm_major" ] && [ -x "/usr/lib/llvm/$llvm_major/bin/llvm-profdata" ]; then
        LLVM_BIN="/usr/lib/llvm/$llvm_major/bin"
    elif command -v llvm-profdata >/dev/null 2>&1; then
        LLVM_BIN="$(dirname "$(command -v llvm-profdata)")"
    else
        echo "coverage: llvm-profdata/llvm-cov not found (set LLVM_BIN)" >&2
        exit 2
    fi
fi

if [ ! -x "$LLVM_BIN/llvm-profdata" ] || [ ! -x "$LLVM_BIN/llvm-cov" ]; then
    echo "coverage: llvm-profdata/llvm-cov not found (set LLVM_BIN)" >&2
    exit 2
fi

LLVM_CXXFILT="$LLVM_BIN/llvm-cxxfilt"
if [ ! -x "$LLVM_CXXFILT" ]; then
    if command -v llvm-cxxfilt >/dev/null 2>&1; then
        LLVM_CXXFILT="$(command -v llvm-cxxfilt)"
    else
        echo "coverage: llvm-cxxfilt not found" >&2
        exit 2
    fi
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "coverage: jq not found" >&2
    exit 2
fi

mkdir -p "$COV_OUT"
rm -rf "$COV_OUT/prof" && mkdir -p "$COV_OUT/prof"

export CARGO_TARGET_DIR="$COV_OUT/build"
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$PWD/$COV_OUT/prof/%p-%m.profraw"

cargo test --workspace
cargo test -p trillby --features qemu-sim

objs="$( (cargo test --workspace --no-run --message-format=json; \
          cargo test -p trillby --features qemu-sim --no-run --message-format=json) \
          | jq -r 'select(.executable != null) | .executable' | sort -u )"

if [ -z "$objs" ]; then
    echo "coverage: no test executables found" >&2
    exit 1
fi

profraws=("$COV_OUT"/prof/*.profraw)
if [ ! -e "${profraws[0]}" ]; then
    echo "coverage: no .profraw profile files generated" >&2
    exit 1
fi

"$LLVM_BIN/llvm-profdata" merge -sparse "${profraws[@]}" -o "$COV_OUT/all.profdata"

object_args=()
while IFS= read -r obj; do
    [ -n "$obj" ] && object_args+=("-object" "$obj")
done <<< "$objs"

"$LLVM_BIN/llvm-cov" export -format=lcov -instr-profile="$COV_OUT/all.profdata" \
    "${object_args[@]}" \
    --ignore-filename-regex='(/\.cargo/|/rustc/|/tests/|/examples/)' > "$COV_OUT/all.lcov"

"$LLVM_BIN/llvm-cov" export -format=text -instr-profile="$COV_OUT/all.profdata" \
    "${object_args[@]}" \
    --ignore-filename-regex='(/\.cargo/|/rustc/|/tests/|/examples/)' > "$COV_OUT/all.json"

jq -r '.data[0].functions[] | "\(.name)\t\(.filenames[0])\t\([.regions[][0]] | min)\t\([.regions[][2]] | max)"' \
    "$COV_OUT/all.json" | "$LLVM_CXXFILT" > "$COV_OUT/demangled_fns.tsv"

# shellcheck disable=SC2046
gawk '
function emit(nr, text) { if (!in_test) print FILENAME ":" nr }
FNR == 1 { in_test = 0; have_prev = 0 }
{
  if (have_prev) {
    t = prev; gsub(/^[ \t]+|[ \t]+$/, "", t)
    if (!in_test && t == "#[cfg(test)]" && $0 ~ /^[ \t]*(pub([ \t]*\([a-z]+\))?[ \t]+)?mod[ \t]+tests([ \t{]|$)/) in_test = 1
    emit(prev_nr, prev)
  }
  prev = $0; prev_nr = FNR; have_prev = 1
}
ENDFILE { if (have_prev) emit(prev_nr, prev); have_prev = 0 }
' $(find crates -path '*/src/*' -name '*.rs' | sort) > "$COV_OUT/prod_lines.txt"

git_rev="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
cur_date="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

gawk -v PWD="$PWD" -v GIT_REV="$git_rev" -v DATE="$cur_date" -v FLOOR="$COVERAGE_FLOOR" -v OUT="$COV_OUT/summary.md" '
function format_ranges(f,    n, i, tmp, start, prev, curr, res, r_str) {
    n = missed_count[f]
    if (n == 0) return ""
    for (i = 1; i <= n; i++) tmp[i] = file_missed[f, i]
    asort(tmp)
    start = tmp[1]
    prev = start
    res = ""
    for (i = 2; i <= n; i++) {
        curr = tmp[i]
        if (curr == prev + 1) {
            prev = curr
        } else {
            if (start == prev) r_str = start
            else r_str = start "-" prev
            if (res == "") res = r_str
            else res = res ", " r_str
            start = curr
            prev = curr
        }
    }
    if (start == prev) r_str = start
    else r_str = start "-" prev
    if (res == "") res = r_str
    else res = res ", " r_str

    if (length(res) > 200) {
        res = substr(res, 1, 197) "..."
    }
    return res
}

BEGIN {
    FS = "\t"
    ex_file_order[1] = "crates/trillby/src/init.rs"
    ex_file["crates/trillby/src/init.rs"] = "PID-1 mounts and ioctls; needs root"
    ex_file_order[2] = "crates/trillby/src/console.rs"
    ex_file["crates/trillby/src/console.rs"] = "VT ioctl"
    num_ex_files = 2

    ex_fn_re[1] = "^trillby::run_app(::\\{closure#[0-9]+\\})?$"
    ex_fn_name[1] = "trillby::run_app"
    ex_fn_reason[1] = "event loop with real hardware"

    ex_fn_re[2] = "^trillby::load_provisioning(::\\{closure#[0-9]+\\})?$"
    ex_fn_name[2] = "trillby::load_provisioning"
    ex_fn_reason[2] = "reads /etc/trillby.bin"

    ex_fn_re[3] = "^trillby::present$"
    ex_fn_name[3] = "trillby::present"
    ex_fn_reason[3] = "writes /dev/fb0"

    ex_fn_re[4] = "^<trillby::fb::FramebufferWriter>::open_fb$"
    ex_fn_name[4] = "<trillby::fb::FramebufferWriter>::open_fb"
    ex_fn_reason[4] = "opens /dev/fb0"

    ex_fn_re[5] = "^<trillby::hw::evdev::EvdevTouch>::new$"
    ex_fn_name[5] = "<trillby::hw::evdev::EvdevTouch>::new"
    ex_fn_reason[5] = "scans /dev/input"

    ex_fn_re[6] = "^<trillby::hw::Hardware>::new$"
    ex_fn_name[6] = "<trillby::hw::Hardware>::new"
    ex_fn_reason[6] = "opens real device fds"

    ex_fn_re[7] = "^<trillby::hw::adapter::DeviceAdapter>::new$"
    ex_fn_name[7] = "<trillby::hw::adapter::DeviceAdapter>::new"
    ex_fn_reason[7] = "opens /dev/ttyAMA0 under qemu-sim"

    ex_fn_re[8] = "^trillby::hw::adapter::configure_network$"
    ex_fn_name[8] = "trillby::hw::adapter::configure_network"
    ex_fn_reason[8] = "network config ioctls"

    ex_fn_re[9] = "^trillby::hw::adapter::default_server_ip$"
    ex_fn_name[9] = "trillby::hw::adapter::default_server_ip"
    ex_fn_reason[9] = "network routing"

    ex_fn_re[10] = "^trillby_server::(main|run|parse_args|usage)$"
    ex_fn_name[10] = "trillby_server::(main|run|parse_args|usage)"
    ex_fn_reason[10] = "run only as SIGKILLed subprocess by e2e/host tests; profile never written"
    num_ex_fns = 10
}
ARGIND == 1 {
    prod_line[$1] = 1
    next
}
ARGIND == 2 {
    fname = $1
    file = $2
    sub("^" PWD "/", "", file)
    min = $3 + 0
    max = $4 + 0
    for (i = 1; i <= num_ex_fns; i++) {
        if (fname ~ ex_fn_re[i]) {
            c = ++fn_span_count[i]
            fn_span_file[i, c] = file
            fn_span_min[i, c] = min
            fn_span_max[i, c] = max
            break
        }
    }
    next
}
ARGIND == 3 {
    if ($0 ~ /^SF:/) {
        sf = substr($0, 4)
        sub("^" PWD "/", "", sf)
    } else if ($0 ~ /^DA:/) {
        split(substr($0, 4), da, ",")
        line = da[1] + 0
        cnt = da[2] + 0
        key = sf ":" line
        if (key in prod_line) {
            if (!(key in da_seen)) {
                da_seen[key] = 1
                da_hit[key] = cnt
            } else if (cnt > da_hit[key]) {
                da_hit[key] = cnt
            }
        }
    }
}
END {
    for (key in da_seen) {
        idx = index(key, ":")
        file = substr(key, 1, idx - 1)
        line = substr(key, idx + 1) + 0

        if (file in ex_file) {
            ex_file_lines[file]++
            continue
        }

        excluded = 0
        for (i = 1; i <= num_ex_fns; i++) {
            sc = fn_span_count[i]
            for (s = 1; s <= sc; s++) {
                if (file == fn_span_file[i, s] && line >= fn_span_min[i, s] && line <= fn_span_max[i, s]) {
                    ex_fn_lines[i]++
                    excluded = 1
                    break
                }
            }
            if (excluded) break
        }
        if (excluded) continue

        file_total[file]++
        all_files[file] = 1
        if (da_hit[key] > 0) {
            file_cov[file]++
            total_cov++
        } else {
            file_missed[file, ++missed_count[file]] = line
        }
        total_count++
    }

    print "# Coverage Summary\n" > OUT
    print "- Date: " DATE > OUT
    print "- Commit: " GIT_REV "\n" > OUT

    print "| File | Covered | Total | % | Missed lines |" > OUT
    print "| --- | --- | --- | --- | --- |" > OUT

    num_files = 0
    for (f in all_files) {
        tot = file_total[f] + 0
        cov = file_cov[f] + 0
        if (tot == 0) continue
        pct = (cov * 100.0) / tot
        num_files++
        file_sort_key[num_files] = sprintf("%06.2f\t%s", pct, f)
    }

    asort(file_sort_key)
    for (i = 1; i <= num_files; i++) {
        split(file_sort_key[i], parts, "\t")
        pct = parts[1] + 0.0
        f = parts[2]
        tot = file_total[f] + 0
        cov = file_cov[f] + 0
        missed_str = format_ranges(f)
        printf("| %s | %d | %d | %.1f%% | %s |\n", f, cov, tot, pct, missed_str) > OUT
    }

    print "\n## Excluded\n" > OUT
    print "| Item | Lines | Reason |" > OUT
    print "| --- | --- | --- |" > OUT
    for (i = 1; i <= num_ex_files; i++) {
        f = ex_file_order[i]
        printf("| %s | %d | %s |\n", f, ex_file_lines[f] + 0, ex_file[f]) > OUT
    }
    for (i = 1; i <= num_ex_fns; i++) {
        printf("| %s | %d | %s |\n", ex_fn_name[i], ex_fn_lines[i] + 0, ex_fn_reason[i]) > OUT
    }

    total_pct = (total_cov * 100.0) / total_count
    total_line = sprintf("TOTAL covered/total = %.1f%%", total_pct)
    print "\n" total_line > OUT

    print total_line
    floor_val = int(total_pct)
    req_floor = FLOOR + 0
    if (floor_val < req_floor) {
        printf("coverage: %.1f%% is below floor %d%%\n", total_pct, req_floor) > "/dev/stderr"
        exit 1
    }
}
' "$COV_OUT/prod_lines.txt" "$COV_OUT/demangled_fns.tsv" "$COV_OUT/all.lcov"
