# DirGuard

DirGuard is a zero-dependency command line tool for directory integrity. It hashes every file under a directory into a JSON manifest, then re-checks that tree later so you can see exactly what was modified, added, removed or merely touched.

It is useful for detecting tampering in config folders, watching a project directory for unexpected edits, or gating a script on whether a tree changed since the last known good scan. It runs on Python 3.10 or newer using only the standard library, so it works on a fresh machine with no installs beyond Python itself.

## Features

- Recursive scanning with SHA256 by default, and SHA1, MD5 or BLAKE2b available via `--algorithm`.
- Detection of changed content, added files, removed files and metadata-only touches, since size and mtime are recorded alongside the hash.
- Symlinks are recorded by their target instead of being silently dereferenced, unless you pass `--follow-symlinks`. A link to a directory is recorded too, and link loops are skipped so a link pointing back up the tree cannot duplicate the whole tree.
- Named pipes, sockets and device nodes are recorded by kind and never opened, since reading a FIFO blocks until a writer appears.
- Ignore patterns on the command line with `--ignore` (repeatable) or from a file with `--ignore-file`. Patterns are stored in the manifest so verification skips the same files, and a bare directory name like `node_modules` prunes that whole directory. Files that later become ignored are reported under `Now ignored` rather than as deletions.
- Unreadable files are recorded as `unreadable` entries and locked directories are captured as scan errors, so permission problems cannot be mistaken for a clean tree.
- Verification warns and fails when the manifest was written for a different directory than the one being checked.
- Manifest to manifest diffing with the `diff` command, which never touches the filesystem.
- Exit code 1 on any integrity failure, 2 for usage errors such as a missing path, a missing manifest or a manifest that is not valid JSON.
- JSON output for the verify and diff reports.
- A manifest written inside the tree it describes is skipped automatically, so it does not show up as an added file on the next verification.

## Installation

```bash
pip install -e .
```

## Usage

Generate a manifest for a directory:

```bash
dirguard generate /path/to/tree --out manifest.json
```

Skip log files and follow symlink targets instead of recording links:

```bash
dirguard generate /path/to/tree --algorithm blake2b --ignore "*.log" --ignore-file .dirguardignore --follow-symlinks
```

Verify the tree against the manifest:

```bash
dirguard verify /path/to/tree --manifest manifest.json
```

Machine readable verification output:

```bash
dirguard verify /path/to/tree --json
```

Compare two manifests without reading the filesystem:

```bash
dirguard diff old.json new.json
```

## Example output

```
Changed (1):
  notes.txt
Added (1):
  injected.sh
Removed (1):
  cfg/app.ini
```

A clean tree prints `Integrity OK: no changes detected.` and exits 0, which makes it easy to chain into a script:

```bash
dirguard verify ~/project --manifest ~/project.manifest.json || echo "project changed since last scan"
```

## What is in the manifest

Each entry is keyed by its path relative to the scanned root and records its type plus the metadata used for comparison:

- A regular file stores its size, mtime and hash.
- A symlink stores its target, so a repointed link counts as a change.
- A special node stores its kind, one of `fifo`, `socket`, `char_device` or `block_device`.
- An unreadable file stores the error instead of a hash.

The manifest also stores the algorithm, the absolute root it was written for, the ignore patterns that were active, and any directories that could not be read.

## Ignore file format

One glob per line, blank lines and lines starting with `#` are skipped:

```
*.log
*.tmp
node_modules
__pycache__
```

Either a bare name like `node_modules` or a trailing slash form like `node_modules/` works, and a bare name prunes the directory so nothing under it is scanned at all.

Verification also reads a `.dirguardignore` sitting next to the manifest, if there is one, so a tree can keep its rules in one file instead of repeating `--ignore-file` on every command.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Clean, or a command that only printed help |
| 1 | Integrity failure, meaning something changed or could not be checked |
| 2 | Usage error, such as a missing path or an unreadable manifest |

## Project layout

```
dirguard/
  engine.py       scanning, hashing and comparison logic
  cli.py          argument parsing and report rendering
tests/
  test_dirguard.py            core behaviour
  test_edge_cases.py          filesystem oddities
  test_edge_cases_round2.py   hangs, loops and error paths
```

## Tests

All three suites run with the standard interpreter and no extra dependencies:

```bash
python3 tests/test_dirguard.py
python3 tests/test_edge_cases.py
python3 tests/test_edge_cases_round2.py
```

The edge case suites cover empty trees, unicode and space filenames, empty and duplicate files, broken symlinks, symlink loops, retargeted links, symlinked directories, FIFOs and sockets, unreadable files and directories, type swaps, legacy manifests, corrupt and missing manifests, a manifest written inside the tree, ignore files, real deletions next to newly ignored files, 2000 file trees, a 64MB file, and the command line surface.
