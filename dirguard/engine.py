import fnmatch
import hashlib
import json
import os
import stat
import time

SUPPORTED_ALGORITHMS = ("sha256", "sha1", "md5", "blake2b")
CHUNK_SIZE = 65536

# Node types that are not regular files and must never be opened for hashing.
# Reading a FIFO blocks until a writer shows up, and character devices can
# stream forever, so both are recorded by kind instead.
SPECIAL_KINDS = (
    (stat.S_ISFIFO, "fifo"),
    (stat.S_ISSOCK, "socket"),
    (stat.S_ISCHR, "char_device"),
    (stat.S_ISBLK, "block_device"),
)


def hash_file(filepath, algorithm="sha256"):
    # Streams the file in chunks so large files never load fully into memory.
    hasher = hashlib.new(algorithm)
    with open(filepath, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def describe_special(mode):
    for predicate, label in SPECIAL_KINDS:
        if predicate(mode):
            return label
    return "unknown"


def load_ignore_patterns(patterns=None, ignore_file=None):
    # Patterns come from the command line plus an optional newline separated file.
    collected = list(patterns or [])
    if ignore_file and os.path.isfile(ignore_file):
        with open(ignore_file, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    collected.append(stripped)
    return collected


def is_ignored(rel_path, patterns):
    # Matches the relative path, the path without a trailing slash, and the bare
    # name, so "*.log" works anywhere and "build" prunes a directory called build.
    if not patterns:
        return False
    trimmed = rel_path.rstrip("/")
    candidates = {rel_path, trimmed}
    base = os.path.basename(trimmed)
    if base:
        candidates.add(base)
    for pattern in patterns:
        for candidate in candidates:
            if fnmatch.fnmatch(candidate, pattern):
                return True
    return False


def scan_directory(root_dir, algorithm="sha256", patterns=None, follow_symlinks=False):
    # Walks the tree and returns an entry per node with size, mtime and digest.
    patterns = patterns or []
    manifest = {
        "algorithm": algorithm,
        "root": os.path.abspath(root_dir),
        "scanned_at": time.time(),
        "ignore_patterns": sorted(patterns),
        "files": {},
        "errors": [],
    }

    def record_walk_error(err):
        # os.walk swallows these by default, which would hide locked directories.
        manifest["errors"].append({
            "path": os.path.relpath(getattr(err, "filename", "") or "", root_dir),
            "error": str(err),
        })

    def identity(path):
        # Directory identity on disk, used to break symlink loops.
        try:
            info = os.stat(path) if follow_symlinks else os.lstat(path)
        except OSError:
            return None
        return (info.st_dev, info.st_ino)

    seen_dirs = set()
    walker = os.walk(root_dir, followlinks=follow_symlinks, onerror=record_walk_error)

    for current, dirs, files in walker:
        current_key = identity(current)
        if current_key is not None:
            if current_key in seen_dirs:
                dirs[:] = []
                continue
            seen_dirs.add(current_key)

        kept_dirs = []
        for name in sorted(dirs):
            full_path = os.path.join(current, name)
            rel_path = os.path.relpath(full_path, root_dir)
            if is_ignored(rel_path + "/", patterns):
                continue

            if os.path.islink(full_path):
                if not follow_symlinks:
                    # A linked directory is a node in its own right. Without
                    # follow_symlinks os.walk never descends into it, so record
                    # the link and stop here instead of leaving it invisible.
                    manifest["files"][rel_path] = {
                        "type": "symlink",
                        "target": os.readlink(full_path),
                    }
                    continue
                # With follow_symlinks on, skip a directory already visited so a
                # link pointing back up the tree cannot duplicate the whole tree.
                key = identity(full_path)
                if key is not None and key in seen_dirs:
                    continue

            kept_dirs.append(name)
        dirs[:] = kept_dirs

        for name in sorted(files):
            full_path = os.path.join(current, name)
            rel_path = os.path.relpath(full_path, root_dir)
            if is_ignored(rel_path, patterns):
                continue

            if os.path.islink(full_path) and not follow_symlinks:
                # Record the link target instead of hashing whatever it points at.
                manifest["files"][rel_path] = {
                    "type": "symlink",
                    "target": os.readlink(full_path),
                }
                continue

            try:
                stat_result = os.stat(full_path)
            except OSError as err:
                manifest["files"][rel_path] = {"type": "unreadable", "error": str(err)}
                continue

            if not stat.S_ISREG(stat_result.st_mode):
                manifest["files"][rel_path] = {
                    "type": "special",
                    "kind": describe_special(stat_result.st_mode),
                    "size": stat_result.st_size,
                    "mtime": stat_result.st_mtime,
                }
                continue

            try:
                manifest["files"][rel_path] = {
                    "type": "file",
                    "size": stat_result.st_size,
                    "mtime": stat_result.st_mtime,
                    "hash": hash_file(full_path, algorithm),
                }
            except OSError as err:
                manifest["files"][rel_path] = {"type": "unreadable", "error": str(err)}

    manifest["file_count"] = len(manifest["files"])
    return manifest


def verify_directory(root_dir, manifest_path):
    # Compares a saved manifest against the current state of the tree.
    with open(manifest_path, "r", encoding="utf-8") as handle:
        saved = json.load(handle)

    algorithm = saved.get("algorithm", "sha256")
    # The manifest records what was skipped at scan time, so verify skips the
    # same things instead of reporting them as newly added.
    patterns = list(saved.get("ignore_patterns", []))
    patterns += load_ignore_patterns(
        ignore_file=os.path.join(os.path.dirname(os.path.abspath(manifest_path)), ".dirguardignore")
    )
    current = scan_directory(root_dir, algorithm=algorithm, patterns=patterns)

    old_files = saved.get("files", {})
    new_files = current.get("files", {})

    report = {
        "changed": [],
        "added": [],
        "removed": [],
        "ignored": [],
        "metadata_only": [],
        "unreadable": [],
        "scan_errors": list(current.get("errors", [])),
    }

    for rel_path, old_entry in old_files.items():
        if rel_path not in new_files:
            # A file that is now covered by an ignore pattern was not deleted, so
            # it belongs in its own bucket instead of showing up as removed.
            if is_ignored(rel_path, patterns):
                report["ignored"].append(rel_path)
            else:
                report["removed"].append(rel_path)
            continue
        new_entry = new_files[rel_path]
        old_type = old_entry.get("type")
        new_type = new_entry.get("type")

        if old_type != new_type:
            report["changed"].append(rel_path)
            continue
        if new_type == "unreadable":
            report["unreadable"].append(rel_path)
            continue
        if new_type == "symlink":
            # A retargeted link points somewhere else, which is a change.
            if old_entry.get("target") != new_entry.get("target"):
                report["changed"].append(rel_path)
            continue
        if new_type == "special":
            if old_entry.get("kind") != new_entry.get("kind"):
                report["changed"].append(rel_path)
            continue
        if old_entry.get("hash") != new_entry.get("hash"):
            report["changed"].append(rel_path)
        elif old_entry.get("size") != new_entry.get("size") or old_entry.get("mtime") != new_entry.get("mtime"):
            # Same content, different size or mtime: touched but not tampered.
            report["metadata_only"].append(rel_path)

    for rel_path in new_files:
        if rel_path not in old_files:
            report["added"].append(rel_path)

    for key in ("changed", "added", "removed", "ignored", "metadata_only", "unreadable"):
        report[key].sort()

    report["clean"] = not (
        report["changed"]
        or report["added"]
        or report["removed"]
        or report["unreadable"]
        or report["scan_errors"]
    )
    report["algorithm"] = algorithm
    report["file_count"] = len(new_files)

    # Verifying the wrong directory otherwise looks like mass deletion and addition.
    saved_root = saved.get("root")
    if saved_root and os.path.normpath(saved_root) != os.path.normpath(os.path.abspath(root_dir)):
        report["root_mismatch"] = {"manifest_root": saved_root, "checked_root": os.path.abspath(root_dir)}
        # Checking a different tree must never be reported as a clean result.
        report["clean"] = False
    return report


def diff_manifests(old_manifest_path, new_manifest_path):
    # Diffs two saved manifests without touching the filesystem.
    with open(old_manifest_path, "r", encoding="utf-8") as handle:
        old = json.load(handle)
    with open(new_manifest_path, "r", encoding="utf-8") as handle:
        new = json.load(handle)

    old_files = old.get("files", {})
    new_files = new.get("files", {})
    changed = sorted(
        rel_path for rel_path, old_entry in old_files.items()
        if rel_path in new_files and (
            old_entry.get("hash") != new_files[rel_path].get("hash") or
            old_entry.get("target") != new_files[rel_path].get("target")
        )
    )
    added = sorted(set(new_files) - set(old_files))
    removed = sorted(set(old_files) - set(new_files))

    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "clean": not (changed or added or removed),
    }


def format_report(report):
    # Renders a report as plain text lines for terminal output.
    lines = []
    if report.get("root_mismatch"):
        mismatch = report["root_mismatch"]
        lines.append(
            "Warning: manifest was written for "
            f"{mismatch['manifest_root']} but {mismatch['checked_root']} was checked."
        )
    if report.get("clean"):
        lines.append("Integrity OK: no changes detected.")
        return "\n".join(lines)

    labels = [
        ("changed", "Changed"),
        ("added", "Added"),
        ("removed", "Removed"),
        ("ignored", "Now ignored"),
        ("metadata_only", "Metadata only"),
        ("unreadable", "Unreadable"),
    ]
    for key, label in labels:
        entries = report.get(key) or []
        if not entries:
            continue
        lines.append(f"{label} ({len(entries)}):")
        for entry in entries:
            lines.append(f"  {entry}")

    scan_errors = report.get("scan_errors") or []
    if scan_errors:
        lines.append(f"Scan errors ({len(scan_errors)}):")
        for entry in scan_errors:
            lines.append(f"  {entry.get('path')}: {entry.get('error')}")
    return "\n".join(lines)
