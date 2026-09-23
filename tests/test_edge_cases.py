import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dirguard.engine import (
    diff_manifests,
    format_report,
    hash_file,
    is_ignored,
    load_ignore_patterns,
    scan_directory,
    verify_directory,
)

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"pass: {name}")
    else:
        print(f"FAIL: {name} {detail}")
        FAILURES.append(name)


def test_empty_directory():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "empty")
        os.makedirs(tree)
        manifest = scan_directory(tree)
        check("empty dir has zero files", manifest["file_count"] == 0)
        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        report = verify_directory(tree, mpath)
        check("empty dir verifies clean", report["clean"], report)


def test_empty_file_and_duplicates():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        open(os.path.join(tree, "empty_a"), "w", encoding="utf-8").close()
        open(os.path.join(tree, "empty_b"), "w", encoding="utf-8").close()
        with open(os.path.join(tree, "same1"), "w", encoding="utf-8") as handle:
            handle.write("identical")
        with open(os.path.join(tree, "same2"), "w", encoding="utf-8") as handle:
            handle.write("identical")
        manifest = scan_directory(tree)
        hashes = {k: v["hash"] for k, v in manifest["files"].items()}
        check("empty files hash identically", hashes["empty_a"] == hashes["empty_b"])
        check("duplicate content hashes match", hashes["same1"] == hashes["same2"])
        check("four entries recorded", manifest["file_count"] == 4)


def test_unicode_and_space_filenames():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(os.path.join(tree, "d ir"))
        names = ["日本語.txt", "with space.txt", "emoji-\U0001F43A.txt", "quote'\".txt"]
        for name in names:
            with open(os.path.join(tree, "d ir", name), "w", encoding="utf-8") as handle:
                handle.write(name)
        manifest = scan_directory(tree)
        check("unicode names recorded", manifest["file_count"] == len(names), sorted(manifest["files"]))
        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        report = verify_directory(tree, mpath)
        check("unicode tree verifies clean", report["clean"], report)


def test_directory_name_ignore():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(os.path.join(tree, "node_modules", "inner"))
        os.makedirs(os.path.join(tree, "src"))
        with open(os.path.join(tree, "node_modules", "pkg.js"), "w", encoding="utf-8") as handle:
            handle.write("dep")
        with open(os.path.join(tree, "node_modules", "inner", "deep.js"), "w", encoding="utf-8") as handle:
            handle.write("dep")
        with open(os.path.join(tree, "src", "app.js"), "w", encoding="utf-8") as handle:
            handle.write("app")
        manifest = scan_directory(tree, patterns=["node_modules"])
        check(
            "plain directory name is ignored",
            sorted(manifest["files"]) == ["src/app.js"],
            sorted(manifest["files"]),
        )


def test_is_ignored_matching():
    check("glob on filename", is_ignored("a/b/c.log", ["*.log"]))
    check("glob on nested path", is_ignored("a/b/c.log", ["a/b/*.log"]))
    check("exact path", is_ignored("keep/this.txt", ["keep/this.txt"]))
    check("directory marker", is_ignored("build/", ["build"]))
    check("nested directory marker", is_ignored("a/build/", ["build"]))
    check("no false positive", not is_ignored("a/b/c.txt", ["*.log"]))


def test_ignore_file_parsing():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ignore")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("# comment\n\n*.tmp\n  *.bak  \n")
        patterns = load_ignore_patterns(["extra"], path)
        check("ignore file comments skipped", "# comment" not in patterns, patterns)
        check("ignore file blanks skipped", "" not in patterns, patterns)
        check("ignore file trimmed", "*.bak" in patterns, patterns)
        check("cli patterns kept", "extra" in patterns, patterns)


def test_broken_symlink():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        os.symlink(os.path.join(tmp, "does_not_exist"), os.path.join(tree, "dangling"))
        manifest = scan_directory(tree)
        entry = manifest["files"]["dangling"]
        check("broken symlink recorded as symlink", entry.get("type") == "symlink", entry)
        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        report = verify_directory(tree, mpath)
        check("broken symlink verifies clean", report["clean"], report)


def test_follow_symlinks_to_missing_target():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        os.symlink(os.path.join(tmp, "gone"), os.path.join(tree, "dangling"))
        manifest = scan_directory(tree, follow_symlinks=True)
        entry = manifest["files"]["dangling"]
        check("dangling link with follow is not fatal", entry.get("type") == "unreadable", entry)


def test_unreadable_file():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        secret = os.path.join(tree, "secret.txt")
        with open(secret, "w", encoding="utf-8") as handle:
            handle.write("classified")
        os.chmod(secret, 0)
        try:
            manifest = scan_directory(tree)
            entry = manifest["files"]["secret.txt"]
            check("unreadable file flagged", entry.get("type") == "unreadable", entry)
        finally:
            os.chmod(secret, 0o644)


def test_unreadable_directory():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        locked = os.path.join(tree, "locked")
        os.makedirs(locked)
        with open(os.path.join(locked, "hidden.txt"), "w", encoding="utf-8") as handle:
            handle.write("hidden")
        os.chmod(locked, 0)
        try:
            manifest = scan_directory(tree)
            check(
                "unreadable directory is reported",
                bool(manifest.get("errors")),
                manifest.get("errors"),
            )
        finally:
            os.chmod(locked, 0o755)


def test_old_manifest_format():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        a_path = os.path.join(tree, "a.txt")
        with open(a_path, "w", encoding="utf-8") as handle:
            handle.write("a")
        legacy = {"files": {"a.txt": {"type": "file", "size": 1, "mtime": 0.0, "hash": hash_file(a_path)}}}
        mpath = os.path.join(tmp, "legacy.json")
        with open(mpath, "w", encoding="utf-8") as handle:
            json.dump(legacy, handle)
        report = verify_directory(tree, mpath)
        check("legacy manifest without metadata keys works", report["clean"], report)


def test_type_swap():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        thing_dir = os.path.join(tree, "thing")
        os.makedirs(thing_dir)
        with open(os.path.join(thing_dir, "inner.txt"), "w", encoding="utf-8") as handle:
            handle.write("inner")
        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w", encoding="utf-8") as handle:
            json.dump(scan_directory(tree), handle)

        os.remove(os.path.join(thing_dir, "inner.txt"))
        os.rmdir(thing_dir)
        with open(thing_dir, "w", encoding="utf-8") as handle:
            handle.write("now a file")

        report = verify_directory(tree, mpath)
        check("dir replaced by file is detected", "thing" in report["changed"] or "thing" in report["added"], report)


def test_diff_identical_and_missing():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("a")
        p1 = os.path.join(tmp, "one.json")
        p2 = os.path.join(tmp, "two.json")
        manifest_data = scan_directory(tree)
        for path in (p1, p2):
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(manifest_data, handle)
        report = diff_manifests(p1, p2)
        check("identical manifests diff clean", report["clean"], report)
        check("diff report renders clean line", "Integrity OK" in format_report(report))


def test_large_file_performance():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        big = os.path.join(tree, "big.bin")
        with open(big, "wb") as handle:
            for _ in range(64):
                handle.write(os.urandom(1024 * 1024))
        start = time.time()
        manifest = scan_directory(tree)
        elapsed = time.time() - start
        check("64MB file hashed quickly", elapsed < 5.0, f"{elapsed:.2f}s")
        check("large file entry complete", manifest["files"]["big.bin"].get("size") == 64 * 1024 * 1024)


def test_relative_and_absolute_paths_agree():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("a")
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            rel = scan_directory("tree")
        finally:
            os.chdir(cwd)
        absolute = scan_directory(tree)
        check(
            "relative and absolute scans agree on keys",
            sorted(rel["files"]) == sorted(absolute["files"]),
            (sorted(rel["files"]), sorted(absolute["files"])),
        )
        check("relative and absolute scans agree on hashes", rel["files"] == absolute["files"])


def test_manifest_root_mismatch_is_visible():
    with tempfile.TemporaryDirectory() as tmp:
        left = os.path.join(tmp, "left")
        right = os.path.join(tmp, "right")
        os.makedirs(left)
        os.makedirs(right)
        with open(os.path.join(left, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("same")
        with open(os.path.join(right, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("same")
        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w", encoding="utf-8") as handle:
            json.dump(scan_directory(left), handle)

        report = verify_directory(right, mpath)
        check("wrong but identical directory is not clean", not report["clean"], report)
        check("root mismatch reported", bool(report.get("root_mismatch")), report)
        check("root mismatch is printed", "Warning" in format_report(report), format_report(report))

        os.remove(os.path.join(right, "a.txt"))
        with open(os.path.join(right, "b.txt"), "w", encoding="utf-8") as handle:
            handle.write("different")
        report = verify_directory(right, mpath)
        check("wrong directory with different files is not clean", not report["clean"], report)

        legacy = {"files": {"a.txt": {"type": "file", "size": 1, "mtime": 0.0, "hash": "x"}}}
        lpath = os.path.join(tmp, "legacy.json")
        with open(lpath, "w", encoding="utf-8") as handle:
            json.dump(legacy, handle)
        report = verify_directory(left, lpath)
        check("manifest without root has no mismatch warning", "root_mismatch" not in report, report)


def test_cli_surface():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=repo_root)

    def run(args):
        result = subprocess.run(
            [sys.executable, "-m", "dirguard.cli"] + args,
            capture_output=True,
            text=True,
            env=env,
        )
        return result.returncode, result.stdout, result.stderr

    code, out, _ = run([])
    check("no args prints help and exits 0", code == 0 and "usage" in out.lower(), (code, out[:80]))

    code, out, err = run(["generate", "/definitely/not/here"])
    check("generate on missing path exits 2", code == 2, (code, out, err))

    code, out, err = run(["verify", "/tmp", "--manifest", "/definitely/not/here.json"])
    check("verify on missing manifest exits 2", code == 2, (code, out, err))

    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w", encoding="utf-8") as handle:
            handle.write("a")
        mpath = os.path.join(tmp, "m.json")
        code, out, err = run(["generate", tree, "--out", mpath, "--algorithm", "sha1"])
        check("generate sha1 exits 0", code == 0, (code, out, err))
        with open(mpath, encoding="utf-8") as handle:
            check("manifest records algorithm", json.load(handle)["algorithm"] == "sha1")
        code, out, err = run(["verify", tree, "--manifest", mpath])
        check("verify clean exits 0", code == 0, (code, out, err))
        code, out, err = run(["generate", tree, "--out", mpath, "--algorithm", "nonsense"])
        check("bad algorithm rejected", code != 0, (code, out, err))
        code, out, err = run(["diff", mpath, mpath])
        check("diff identical exits 0", code == 0, (code, out, err))


def main():
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            try:
                func()
            except Exception as err:
                print(f"FAIL: {name} raised {type(err).__name__}: {err}")
                FAILURES.append(name)
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failing checks: {FAILURES}")
        return 1
    print("all edge case checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())