#!/usr/bin/env bash
# Tests for file_permission_auditor.sh.
#
# Run with:  bash test_file_permission_auditor.sh
#
# We source the library under test and call its functions directly.  The
# tests create a temporary directory tree, chmod specific files, run the
# scanner, and compare the sorted output against an expected set.  Sorting
# makes the assertions independent of `find` traversal order, which is not
# guaranteed across filesystems.

set -euo pipefail

# shellcheck source=file_permission_auditor.sh
source "$(dirname "$0")/file_permission_auditor.sh"

# assert_eq <expected> <actual> <message>
#   TAP-like assertion.  Prints ok/not ok and exits non-zero on mismatch.
assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="$3"
    if [[ "$expected" == "$actual" ]]; then
        printf 'ok - %s\n' "$msg"
    else
        printf 'not ok - %s\n' "$msg"
        printf '  expected: %q\n' "$expected"
        printf '  actual:   %q\n' "$actual"
        exit 1
    fi
}

# assert_rc <expected_rc> <actual_rc> <message>
assert_rc() {
    local expected="$1"
    local actual="$2"
    local msg="$3"
    if [[ "$expected" -eq "$actual" ]]; then
        printf 'ok - %s\n' "$msg"
    else
        printf 'not ok - %s\n' "$msg"
        printf '  expected rc: %d\n' "$expected"
        printf '  actual rc:   %d\n' "$actual"
        exit 1
    fi
}

# --- fixtures ---------------------------------------------------------------

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# A clean tree: no risky bits.
mkdir -p "$TMPDIR_TEST/clean"
printf 'hello\n' > "$TMPDIR_TEST/clean/normal.txt"
chmod 0644 "$TMPDIR_TEST/clean/normal.txt"

# A tree with exactly one world-writable file.
mkdir -p "$TMPDIR_TEST/ww"
printf 'x\n' > "$TMPDIR_TEST/ww/writable.txt"
chmod 0666 "$TMPDIR_TEST/ww/writable.txt"
printf 'y\n' > "$TMPDIR_TEST/ww/safe.txt"
chmod 0644 "$TMPDIR_TEST/ww/safe.txt"

# A tree with setuid and setgid files.  chmod 4755 and 2755 may be rejected
# on filesystems mounted nosuid; we detect that and skip the assertion rather
# than fail spuriously.  (Containers usually allow it.)
mkdir -p "$TMPDIR_TEST/suid"
printf 's\n' > "$TMPDIR_TEST/suid/suid.bin"
chmod 4755 "$TMPDIR_TEST/suid/suid.bin"
printf 'g\n' > "$TMPDIR_TEST/suid/sgid.bin"
chmod 2755 "$TMPDIR_TEST/suid/sgid.bin"
printf 'n\n' > "$TMPDIR_TEST/suid/plain.bin"
chmod 0755 "$TMPDIR_TEST/suid/plain.bin"

# A nested tree to exercise recursion.
mkdir -p "$TMPDIR_TEST/nested/a/b"
printf 'deep\n' > "$TMPDIR_TEST/nested/a/b/deep.txt"
chmod 0666 "$TMPDIR_TEST/nested/a/b/deep.txt"
printf 'shallow\n' > "$TMPDIR_TEST/nested/shallow.txt"
chmod 0644 "$TMPDIR_TEST/nested/shallow.txt"

# A filename with a space, to prove we do not split on whitespace.
mkdir -p "$TMPDIR_TEST/spaces"
printf 'z\n' > "$TMPDIR_TEST/spaces/has space.txt"
chmod 0666 "$TMPDIR_TEST/spaces/has space.txt"

# --- tests ------------------------------------------------------------------

# 1. Non-recursive scan of a clean tree yields nothing.
out=$(fpa_scan "$TMPDIR_TEST/clean")
assert_eq "" "$out" "clean tree produces no findings"

# 2. Non-recursive scan finds a world-writable file.
out=$(fpa_scan "$TMPDIR_TEST/ww" | sort)
expected="$TMPDIR_TEST/ww/writable.txt:0666:WORLD_WRITABLE"
assert_eq "$expected" "$out" "world-writable file is reported"

# 3. Non-recursive scan does not descend into subdirectories.
out=$(fpa_scan "$TMPDIR_TEST/nested" | sort)
assert_eq "" "$out" "non-recursive scan ignores nested findings"

# 4. Recursive scan finds the nested world-writable file.
out=$(fpa_scan_dir "$TMPDIR_TEST/nested" | sort)
expected="$TMPDIR_TEST/nested/a/b/deep.txt:0666:WORLD_WRITABLE"
assert_eq "$expected" "$out" "recursive scan finds nested world-writable file"

# 5. Setuid and setgid are reported.  Skip if the filesystem refused the
#    chmod (some nosuid mounts silently clear the bits).
mode_suid=$(stat -c '%a' "$TMPDIR_TEST/suid/suid.bin")
mode_sgid=$(stat -c '%a' "$TMPDIR_TEST/suid/sgid.bin")
if [[ "$mode_suid" == 4755 && "$mode_sgid" == 2755 ]]; then
    out=$(fpa_scan "$TMPDIR_TEST/suid" | sort)
    expected=$(printf '%s\n%s' \
        "$TMPDIR_TEST/suid/sgid.bin:2755:SETGID" \
        "$TMPDIR_TEST/suid/suid.bin:4755:SETUID" | sort)
    assert_eq "$expected" "$out" "setuid and setgid files are reported"
else
    printf 'ok - setuid/setgid chmod not supported here, skipping\n'
fi

# 6. A file with both setuid and world-writable yields two lines.
mkdir -p "$TMPDIR_TEST/both"
printf 'b\n' > "$TMPDIR_TEST/both/both.bin"
chmod 4777 "$TMPDIR_TEST/both/both.bin"
mode_both=$(stat -c '%a' "$TMPDIR_TEST/both/both.bin")
if [[ "$mode_both" == 4777 ]]; then
    out=$(fpa_scan "$TMPDIR_TEST/both" | sort)
    expected=$(printf '%s\n%s' \
        "$TMPDIR_TEST/both/both.bin:4777:SETUID" \
        "$TMPDIR_TEST/both/both.bin:4777:WORLD_WRITABLE" | sort)
    assert_eq "$expected" "$out" "file with both bits yields two findings"
else
    printf 'ok - 4777 chmod not supported here, skipping\n'
fi

# 7. Filenames with spaces survive the round trip.
out=$(fpa_scan "$TMPDIR_TEST/spaces" | sort)
expected="$TMPDIR_TEST/spaces/has space.txt:0666:WORLD_WRITABLE"
assert_eq "$expected" "$out" "filename with space is handled"

# 8. Missing argument returns 1 and prints to stderr.
set +e
fpa_scan >/dev/null 2>&1
rc=$?
set -e
assert_rc 1 "$rc" "fpa_scan with no argument returns 1"

# 9. Non-directory argument returns 1.
set +e
fpa_scan "$TMPDIR_TEST/clean/normal.txt" >/dev/null 2>&1
rc=$?
set -e
assert_rc 1 "$rc" "fpa_scan on a regular file returns 1"

# 10. fpa_scan_dir on a missing directory returns 1.
set +e
fpa_scan_dir "$TMPDIR_TEST/does-not-exist" >/dev/null 2>&1
rc=$?
set -e
assert_rc 1 "$rc" "fpa_scan_dir on missing directory returns 1"

# 11. Directories are not reported even if world-writable.
mkdir -p "$TMPDIR_TEST/dirww"
chmod 0777 "$TMPDIR_TEST/dirww"
out=$(fpa_scan "$TMPDIR_TEST/dirww" | sort)
assert_eq "" "$out" "world-writable directory is not reported"

printf '1..11\n'
