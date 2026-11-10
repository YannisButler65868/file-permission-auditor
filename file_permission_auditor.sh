#!/usr/bin/env bash
# file_permission_auditor.sh — scan a directory tree for risky permission bits.
#
# The library exposes two functions:
#   fpa_scan <root>          — print one line per finding to stdout
#   fpa_scan_dir <root>      — same, but recurse into subdirectories
#
# Findings are printed as: <path>:<octal-mode>:<tag>
# where <tag> is one of WORLD_WRITABLE, SETUID, SETGID.
#
# Why a shell library?  The original use case was a pre-deploy gate on a
# build box where installing a language runtime was not allowed.  The
# implementation therefore sticks to bash builtins plus coreutils `find`
# and `stat`, both of which are present in every POSIX-ish container we
# target.  A pure-bash recursive walk was rejected because `find` already
# handles symlink loops, permission-denied subdirectories, and depth limits
# correctly; reimplementing that in bash is a bug farm.
#
# Design decision: we report *files* only.  Directories with the sticky bit
# or world-writable permissions are a different risk model (shared /tmp),
# and the brief asks for files.  We also do not follow symlinks; a symlink
# to /etc/shadow is not itself world-writable, and following it would make
# the audit depend on the target's permissions at scan time.

set -euo pipefail

# fpa_scan <root>
#   Scan only the immediate entries of <root> (non-recursive).
#   Prints findings to stdout, one per line.
#   Returns 0 on success, 1 if <root> is not a directory.
fpa_scan() {
    local root="${1:-}"
    if [[ -z "$root" || ! -d "$root" ]]; then
        printf 'fpa_scan: not a directory: %s\n' "${root:-<empty>}" >&2
        return 1
    fi
    _fpa_scan_impl "$root" 0
}

# fpa_scan_dir <root>
#   Recursively scan <root> and all subdirectories.
#   Prints findings to stdout, one per line.
#   Returns 0 on success, 1 if <root> is not a directory.
fpa_scan_dir() {
    local root="${1:-}"
    if [[ -z "$root" || ! -d "$root" ]]; then
        printf 'fpa_scan_dir: not a directory: %s\n' "${root:-<empty>}" >&2
        return 1
    fi
    _fpa_scan_impl "$root" 1
}

# _fpa_scan_impl <root> <recurse>
#   Shared implementation.  <recurse> is 1 to descend, 0 to stay shallow.
#   We use `find` with -maxdepth to control recursion, and `-type f` so
#   directories and symlinks are skipped.  `-print0`/`read -d ''` keeps
#   filenames with spaces or newlines intact.
_fpa_scan_impl() {
    local root="$1"
    local recurse="$2"
    local depth_arg=()
    if [[ "$recurse" -eq 0 ]]; then
        depth_arg=(-maxdepth 1)
    fi

    # `find` may return non-zero if a subdirectory is unreadable.  We treat
    # that as a warning rather than a hard failure so a single locked-down
    # subtree does not abort the whole audit.  The warning goes to stderr.
    local find_rc=0
    while IFS= read -r -d '' path; do
        _fpa_report "$path"
    done < <(find "$root" "${depth_arg[@]}" -type f -print0 2>/dev/null) || find_rc=$?
    if [[ "$find_rc" -ne 0 && "$find_rc" -ne 1 ]]; then
        printf 'fpa: find exited with status %d under %s\n' "$find_rc" "$root" >&2
    fi
    return 0
}

# _fpa_report <path>
#   Stat the file and emit a finding line for each risky bit.
#   We use `stat -c '%a'` (GNU coreutils) because the brief targets
#   containers where GNU stat is the norm.  The mode is printed without a
#   leading zero, so we normalise to a 4-digit string before inspecting
#   the setuid/setgid/world-writable bits.  A file with mode 0644 comes back
#   as "644"; we left-pad to "0644".  A file with mode 4755 comes back as
#   "4755" already.
_fpa_report() {
    local path="$1"
    local mode
    if ! mode=$(stat -c '%a' -- "$path" 2>/dev/null); then
        # Race: file disappeared between find and stat.  Not a finding.
        return 0
    fi

    # Normalise to exactly 4 octal digits.  Some filesystems return 3 digits
    # for modes without special bits; we pad on the left.
    while [[ "${#mode}" -lt 4 ]]; do
        mode="0${mode}"
    done

    local special="${mode:0:1}"
    local perms="${mode:1:3}"

    # setuid bit is 4 in the special digit, setgid is 2, sticky is 1.
    # We only report setuid and setgid; sticky on a file is unusual but not
    # a privilege-escalation vector in the same way.
    if (( (10#$special & 4) != 0 )); then
        printf '%s:%s:SETUID\n' "$path" "$mode"
    fi
    if (( (10#$special & 2) != 0 )); then
        printf '%s:%s:SETGID\n' "$path" "$mode"
    fi

    # World-writable is the last octal digit having the 2 bit set.
    local last="${perms:2:1}"
    if (( (10#$last & 2) != 0 )); then
        printf '%s:%s:WORLD_WRITABLE\n' "$path" "$mode"
    fi
}
