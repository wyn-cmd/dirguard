# Tests for update (incremental hashing) and --quiet, run with the standard
# interpreter and no dependencies, the same way as the other suites here.

import io
import json
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dirguard.cli import main
from dirguard.engine import scan_directory

PASSED = []
FAILED = []

def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"pass: {name}")
    else:
        FAILED.append((name, detail))
        print(f"FAIL: {name} -- {detail}")

def run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()

def make_tree(root):
    os.makedirs(os.path.join(root, "sub"))
    with open(os.path.join(root, "a.txt"), "w") as f:
        f.write("one")
    with open(os.path.join(root, "sub", "b.txt"), "w") as f:
        f.write("two")


def test_update_reuses_hashes_when_nothing_changed():
    work = tempfile.mkdtemp(prefix="dirguard-update-test-")
    try:
        make_tree(work)
        manifest_path = os.path.join(work, "m.json")
        run_cli(["generate", work, "--out", manifest_path])
        code, out, err = run_cli(["update", work, "--out", manifest_path])
        check("update exits 0", code == 0, err)
        check("update reused both hashes", "reused 2 unchanged hash" in out, out)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_update_rehashes_a_changed_file_only():
    work = tempfile.mkdtemp(prefix="dirguard-update-test-")
    try:
        make_tree(work)
        manifest_path = os.path.join(work, "m.json")
        run_cli(["generate", work, "--out", manifest_path])
        with open(manifest_path) as f:
            before = json.load(f)
        import time
        time.sleep(1.1)  # mtime resolution on some filesystems is 1 second
        with open(os.path.join(work, "a.txt"), "w") as f:
            f.write("one-changed")
        code, out, err = run_cli(["update", work, "--out", manifest_path])
        with open(manifest_path) as f:
            after = json.load(f)
        check("update exits 0 on a changed file", code == 0, err)
        check("update reused exactly one hash", "reused 1 unchanged hash" in out, out)
        check("the changed file's hash actually changed",
              before["files"]["a.txt"]["hash"] != after["files"]["a.txt"]["hash"])
        check("the untouched file's hash is identical",
              before["files"]["sub/b.txt"]["hash"] == after["files"]["sub/b.txt"]["hash"])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_update_ignores_a_mismatched_algorithm_baseline():
    work = tempfile.mkdtemp(prefix="dirguard-update-test-")
    try:
        make_tree(work)
        baseline_path = os.path.join(work, "md5.json")
        run_cli(["generate", work, "--out", baseline_path, "--algorithm", "md5"])
        code, out, err = run_cli(["update", work, "--out", os.path.join(work, "m.json"),
                                   "--baseline", baseline_path, "--algorithm", "sha256"])
        check("mismatched algorithm baseline is not reused", "reused 0 unchanged hash" in out, out)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_quiet_suppresses_output_but_keeps_the_exit_code():
    work = tempfile.mkdtemp(prefix="dirguard-quiet-test-")
    try:
        make_tree(work)
        manifest_path = os.path.join(work, "m.json")
        run_cli(["generate", work, "--out", manifest_path])
        code, out, err = run_cli(["verify", work, "--manifest", manifest_path, "--quiet"])
        check("quiet clean verify exits 0", code == 0)
        check("quiet clean verify prints nothing", out == "" and err == "")

        with open(os.path.join(work, "a.txt"), "w") as f:
            f.write("tampered")
        code2, out2, err2 = run_cli(["verify", work, "--manifest", manifest_path, "--quiet"])
        check("quiet dirty verify exits 1", code2 == 1)
        check("quiet dirty verify still prints nothing", out2 == "" and err2 == "")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_manifest_records_a_version():
    work = tempfile.mkdtemp(prefix="dirguard-version-test-")
    try:
        make_tree(work)
        manifest = scan_directory(work)
        check("manifest carries a version field", "version" in manifest, manifest)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    test_update_reuses_hashes_when_nothing_changed()
    test_update_rehashes_a_changed_file_only()
    test_update_ignores_a_mismatched_algorithm_baseline()
    test_quiet_suppresses_output_but_keeps_the_exit_code()
    test_manifest_records_a_version()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name}: {detail}")
    if FAILED:
        sys.exit(1)
    print("all update/quiet checks passed")
