import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dirguard.engine import (
    diff_manifests,
    format_report,
    scan_directory,
    verify_directory,
)

FAILURES = []
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(name, condition, detail=""):
    if condition:
        print(f"pass: {name}")
    else:
        print(f"FAIL: {name} {detail}")
        FAILURES.append(name)


def cli(args, timeout=25):
    result = subprocess.run(
        [sys.executable, "-m", "dirguard.cli"] + args,
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=REPO_ROOT),
        timeout=timeout,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def test_fifo_does_not_hang():
    # Reading a FIFO blocks forever unless a writer appears, so it must be
    # recorded by kind instead of being opened.
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "normal.txt"), "w") as handle:
            handle.write("ok")
        os.mkfifo(os.path.join(tree, "pipe"))

        start = time.time()
        manifest = scan_directory(tree)
        elapsed = time.time() - start
        check("fifo scan returns promptly", elapsed < 3.0, f"{elapsed:.2f}s")
        entry = manifest["files"].get("pipe", {})
        check("fifo recorded as special", entry.get("type") == "special" and entry.get("kind") == "fifo", entry)
        check("regular file still hashed", manifest["files"]["normal.txt"].get("type") == "file", manifest["files"])

        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w") as handle:
            json.dump(manifest, handle)
        report = verify_directory(tree, mpath)
        check("tree with fifo verifies clean", report["clean"], report)


def test_socket_file_is_recorded():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        sock_path = os.path.join(tree, "app.sock")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(sock_path)
        try:
            manifest = scan_directory(tree)
            entry = manifest["files"].get("app.sock", {})
            check("socket recorded as special", entry.get("type") == "special" and entry.get("kind") == "socket", entry)
        finally:
            sock.close()


def test_symlink_loop_is_not_duplicated():
    # With --follow-symlinks a link back to an ancestor must not walk the tree
    # again or the same files get recorded over and over.
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(os.path.join(tree, "sub"))
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("a")
        with open(os.path.join(tree, "sub", "b.txt"), "w") as handle:
            handle.write("b")
        os.symlink(tree, os.path.join(tree, "sub", "back"))

        start = time.time()
        manifest = scan_directory(tree, follow_symlinks=True)
        elapsed = time.time() - start
        check("loop scan returns promptly", elapsed < 3.0, f"{elapsed:.2f}s")
        check("loop does not duplicate entries", manifest["file_count"] == 2, sorted(manifest["files"]))
        check("loop keeps real files", sorted(manifest["files"]) == ["a.txt", os.path.join("sub", "b.txt")], sorted(manifest["files"]))


def test_symlinked_directory_is_visible():
    # Without follow_symlinks os.walk never descends into a linked directory, so
    # the link itself has to be recorded or it disappears from the manifest.
    with tempfile.TemporaryDirectory() as tmp:
        outside = os.path.join(tmp, "outside")
        tree = os.path.join(tmp, "tree")
        os.makedirs(outside)
        os.makedirs(tree)
        with open(os.path.join(outside, "target.txt"), "w") as handle:
            handle.write("outside")
        os.symlink(outside, os.path.join(tree, "linked_dir"))
        with open(os.path.join(tree, "real.txt"), "w") as handle:
            handle.write("real")

        manifest = scan_directory(tree)
        entry = manifest["files"].get("linked_dir", {})
        check("linked directory recorded as symlink", entry.get("type") == "symlink", entry)
        check("linked directory not walked", "linked_dir/target.txt" not in manifest["files"], sorted(manifest["files"]))


def test_symlink_retarget_detected():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        one = os.path.join(tmp, "one.txt")
        two = os.path.join(tmp, "two.txt")
        for path, text in ((one, "one"), (two, "two")):
            with open(path, "w") as handle:
                handle.write(text)
        link = os.path.join(tree, "link.txt")
        os.symlink(one, link)

        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w") as handle:
            json.dump(scan_directory(tree), handle)

        report = verify_directory(tree, mpath)
        check("unchanged symlink is clean", report["clean"], report)

        os.remove(link)
        os.symlink(two, link)
        report = verify_directory(tree, mpath)
        check("retargeted symlink is detected", report["changed"] == ["link.txt"], report)


def test_corrupt_manifest_exits_cleanly():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("a")

        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w") as handle:
            handle.write("{not json")
        code, out, err = cli(["verify", tree, "--manifest", bad])
        check("corrupt manifest exits 2", code == 2, (code, out, err))
        check("corrupt manifest has no traceback", "Traceback" not in err, err)
        check("corrupt manifest message is clear", "not valid JSON" in err, err)

        code, out, err = cli(["diff", bad, bad])
        check("diff on corrupt manifest exits 2", code == 2 and "Traceback" not in err, (code, err))

        empty = os.path.join(tmp, "empty.json")
        with open(empty, "w") as handle:
            handle.write('{"algorithm": "sha256"}')
        code, out, err = cli(["verify", tree, "--manifest", empty])
        check("manifest without files section exits 2", code == 2 and "files section" in err, (code, err))

        code, out, err = cli(["verify", tree, "--manifest", os.path.join(tmp, "missing.json")])
        check("missing manifest exits 2", code == 2 and "not found" in err, (code, err))


def test_verify_file_path_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        target = os.path.join(tree, "a.txt")
        with open(target, "w") as handle:
            handle.write("a")
        mpath = os.path.join(tmp, "m.json")
        cli(["generate", tree, "--out", mpath])

        code, out, err = cli(["verify", target, "--manifest", mpath])
        check("verify on a file exits 2", code == 2, (code, out, err))
        check("verify on a file says so", "Not a directory" in err, err)

        code, out, err = cli(["generate", target, "--out", mpath])
        check("generate on a file exits 2", code == 2 and "Not a directory" in err, (code, err))


def test_manifest_inside_tree_is_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("a")
        manifest_path = os.path.join(tree, "manifest.json")

        code, out, err = cli(["generate", tree, "--out", manifest_path])
        check("generate inside tree succeeds", code == 0, (code, out, err))
        check("generate warns about the manifest location", "inside" in out, out)

        code, out, err = cli(["verify", tree, "--manifest", manifest_path])
        check("verify stays clean with manifest inside the tree", code == 0, (code, out, err))
        check("verify output confirms clean", "Integrity OK" in out, out)


def test_manifest_outside_tree_for_comparison():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("a")
        mpath = os.path.join(tmp, "m.json")
        code, out, err = cli(["generate", tree, "--out", mpath])
        check("outside manifest has no warning", "inside" not in out, out)
        code, out, err = cli(["verify", tree, "--manifest", mpath])
        check("outside manifest verifies clean", code == 0 and "Integrity OK" in out, (code, out, err))


def test_dirguardignore_file_next_to_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "keep.txt"), "w") as handle:
            handle.write("keep")
        with open(os.path.join(tree, "noise.tmp"), "w") as handle:
            handle.write("noise")
        with open(os.path.join(tree, "gone.txt"), "w") as handle:
            handle.write("bye")
        mpath = os.path.join(tmp, "m.json")
        cli(["generate", tree, "--out", mpath])
        with open(os.path.join(tmp, ".dirguardignore"), "w") as handle:
            handle.write("*.tmp\n")

        # A newly ignored file is not a deletion, but a real deletion still is.
        with open(os.path.join(tree, "another.tmp"), "w") as handle:
            handle.write("noise")
        os.remove(os.path.join(tree, "gone.txt"))

        code, out, err = cli(["verify", tree, "--manifest", mpath, "--json"])
        report = json.loads(out)
        check("newly ignored file is not called removed", "noise.tmp" not in report["removed"], report)
        check("newly ignored file is listed as ignored", "noise.tmp" in report["ignored"], report)
        check("real deletion is still detected", report["removed"] == ["gone.txt"], report)
        check("verify exits 1 for the real deletion", code == 1, (code, out[:200]))
        check("ignored bucket does not break the report text", "Now ignored" in format_report(report), format_report(report))


def test_diff_exit_codes():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        target = os.path.join(tree, "a.txt")
        with open(target, "w") as handle:
            handle.write("one")
        old = os.path.join(tmp, "old.json")
        new = os.path.join(tmp, "new.json")
        cli(["generate", tree, "--out", old])
        with open(target, "w") as handle:
            handle.write("two")
        cli(["generate", tree, "--out", new])

        code, out, err = cli(["diff", old, new])
        check("diff with changes exits 1", code == 1, (code, out, err))
        check("diff names the changed file", "a.txt" in out, out)

        code, out, err = cli(["diff", new, new])
        check("diff of identical manifests exits 0", code == 0, (code, out, err))

        report = diff_manifests(old, new)
        check("diff report has no scan_errors key requirement", "Integrity OK" not in format_report(report), report)


def test_many_files_performance():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        for bucket in range(40):
            folder = os.path.join(tree, f"dir{bucket:02d}")
            os.makedirs(folder)
            for index in range(50):
                with open(os.path.join(folder, f"file{index:03d}.txt"), "w") as handle:
                    handle.write(f"{bucket}-{index}")
        start = time.time()
        manifest = scan_directory(tree)
        elapsed = time.time() - start
        check("2000 files scanned quickly", elapsed < 10.0, f"{elapsed:.2f}s")
        check("2000 files all recorded", manifest["file_count"] == 2000, manifest["file_count"])

        mpath = os.path.join(tmp, "m.json")
        with open(mpath, "w") as handle:
            json.dump(manifest, handle)
        report = verify_directory(tree, mpath)
        check("2000 file tree verifies clean", report["clean"], report["added"][:5])


def test_json_output_parses_with_awkward_names():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        awkward = ['new\nline.txt', 'quote".txt', "tab\there.txt", "back\\slash.txt"]
        for index, name in enumerate(awkward):
            with open(os.path.join(tree, name), "w") as handle:
                handle.write(str(index))
        mpath = os.path.join(tmp, "m.json")
        cli(["generate", tree, "--out", mpath])
        code, out, err = cli(["verify", tree, "--manifest", mpath, "--json"])
        check("awkward names verify clean", code == 0, (code, out[:200], err))
        parsed = json.loads(out)
        check("json report parses", parsed.get("clean") is True, parsed.get("clean"))


def test_readonly_tree():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("a")
        os.chmod(tree, 0o555)
        try:
            manifest = scan_directory(tree)
            check("read only tree scans fine", manifest["file_count"] == 1, manifest["files"])
        finally:
            os.chmod(tree, 0o755)


def main():
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            try:
                func()
            except subprocess.TimeoutExpired as err:
                print(f"FAIL: {name} timed out: {err}")
                FAILURES.append(name)
            except Exception as err:
                print(f"FAIL: {name} raised {type(err).__name__}: {err}")
                FAILURES.append(name)
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failing checks: {FAILURES}")
        return 1
    print("all round two checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
