import json
import os
import sys
import tempfile

# Allow running this file directly as python3 tests/test_dirguard.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dirguard.engine import diff_manifests, format_report, hash_file, scan_directory, verify_directory


def make_tree(root):
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    with open(os.path.join(root, "a.txt"), "w") as handle:
        handle.write("alpha")
    with open(os.path.join(root, "sub", "b.txt"), "w") as handle:
        handle.write("beta")
    with open(os.path.join(root, "skip.log"), "w") as handle:
        handle.write("noise")


def test_clean_verify():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        make_tree(tree)
        manifest_path = os.path.join(tmp, "manifest.json")
        manifest = scan_directory(tree, patterns=["*.log"])
        with open(manifest_path, "w") as handle:
            json.dump(manifest, handle)

        assert manifest["file_count"] == 2
        report = verify_directory(tree, manifest_path)
        assert report["clean"], report
        assert not report["added"], report
        print("clean verify test passed")


def test_change_add_remove():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        make_tree(tree)
        manifest_path = os.path.join(tmp, "manifest.json")
        with open(manifest_path, "w") as handle:
            json.dump(scan_directory(tree, patterns=["*.log"]), handle)

        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("tampered")
        os.remove(os.path.join(tree, "sub", "b.txt"))
        with open(os.path.join(tree, "new.txt"), "w") as handle:
            handle.write("new")

        report = verify_directory(tree, manifest_path)
        assert report["changed"] == ["a.txt"], report
        assert report["removed"] == [os.path.join("sub", "b.txt")], report
        assert report["added"] == ["new.txt"], report
        assert not report["clean"]
        print("change/add/remove test passed")


def test_metadata_only():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        make_tree(tree)
        manifest_path = os.path.join(tmp, "manifest.json")
        with open(manifest_path, "w") as handle:
            json.dump(scan_directory(tree, patterns=["*.log"]), handle)

        # Rewrite identical content so the mtime moves but the hash does not.
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("alpha")

        report = verify_directory(tree, manifest_path)
        assert report["metadata_only"] == ["a.txt"], report
        assert report["clean"], report
        print("metadata only test passed")


def test_ignore_patterns():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        make_tree(tree)
        manifest = scan_directory(tree, patterns=["*.log", "sub/*"])
        assert sorted(manifest["files"]) == ["a.txt"], manifest["files"]
        print("ignore pattern test passed")


def test_manifest_algos():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "f.txt")
        with open(path, "w") as handle:
            handle.write("alpha")
        sha = hash_file(path, "sha256")
        md5 = hash_file(path, "md5")
        assert len(sha) == 64
        assert len(md5) == 32
        assert sha != md5
        print("algorithm test passed")


def test_diff_manifests():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        make_tree(tree)
        old_path = os.path.join(tmp, "old.json")
        new_path = os.path.join(tmp, "new.json")

        with open(old_path, "w") as handle:
            json.dump(scan_directory(tree, patterns=["*.log"]), handle)
        with open(os.path.join(tree, "a.txt"), "w") as handle:
            handle.write("changed")
        with open(new_path, "w") as handle:
            json.dump(scan_directory(tree, patterns=["*.log"]), handle)

        report = diff_manifests(old_path, new_path)
        assert report["changed"] == ["a.txt"], report
        assert "a.txt" in format_report(report)
        print("manifest diff test passed")


def test_missing_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        try:
            verify_directory(tmp, os.path.join(tmp, "nope.json"))
        except FileNotFoundError:
            print("missing manifest test passed")
            return
        raise AssertionError("expected FileNotFoundError")


def test_symlink():
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree, exist_ok=True)
        target = os.path.join(tmp, "target.txt")
        with open(target, "w") as handle:
            handle.write("pointed at")
        os.symlink(target, os.path.join(tree, "link.txt"))

        manifest = scan_directory(tree)
        entry = manifest["files"]["link.txt"]
        assert entry["type"] == "symlink", entry
        assert entry["target"] == target, entry
        print("symlink test passed")


def main():
    test_clean_verify()
    test_change_add_remove()
    test_metadata_only()
    test_ignore_patterns()
    test_manifest_algos()
    test_diff_manifests()
    test_missing_manifest()
    test_symlink()
    print("all dirguard tests passed")


if __name__ == "__main__":
    main()
