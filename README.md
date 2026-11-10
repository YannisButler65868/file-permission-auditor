# file-permission-auditor

Scans a directory tree and reports files with world-writable, setuid, or setgid bits set.

## Usage

```bash
source ./file_permission_auditor.sh

# Non-recursive: only the immediate entries of ./build
fpa_scan ./build

# Recursive: the whole tree under ./build
fpa_scan_dir ./build
```

Each finding is one line on stdout:

```
/path/to/file:0666:WORLD_WRITABLE
/path/to/binary:4755:SETUID
/path/to/binary:2755:SETGID
```

The mode is always four octal digits. A file with both setuid and world-writable bits produces two lines, one per tag. The functions return 0 on success and 1 if the argument is missing or is not a directory.

## Why this exists

Deploy gates on build boxes often run in a container where installing a runtime is not an option. The audit itself is small — `find` plus `stat` — so a shell library keeps the gate dependency-free. The trade-off is that we rely on GNU coreutils (`find -print0`, `stat -c`); a BSD userland would need different flags. That was acceptable because the target environment is a Linux container, and the alternative (a pure-bash recursive walk) would have to reimplement symlink-loop detection and permission-denied handling, which is where the bugs live.

## The awkward edge

We report files only, not directories. A world-writable directory is a different risk profile (think shared `/tmp` with the sticky bit) and the brief asked for files, so a directory with mode 0777 is deliberately silent. If you need directory findings, that is a separate audit.

We also do not follow symlinks. A symlink pointing at a world-writable target is not itself world-writable, and following it would make the result depend on the target's permissions at scan time. The scanner reports the link's own mode, which for a symlink is not meaningful on Linux — so in practice symlinks are skipped by `find -type f`.

## Testing

```bash
bash test_file_permission_auditor.sh
```

The tests create a temporary tree, chmod specific files, and compare sorted output. Setuid/setgid assertions are skipped on filesystems that silently clear those bits (for example `nosuid` mounts).
