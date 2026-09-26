import argparse
import json
import os
import sys

from dirguard.engine import (
    SUPPORTED_ALGORITHMS,
    diff_manifests,
    format_report,
    load_ignore_patterns,
    scan_directory,
    verify_directory,
)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dirguard",
        description="Generate and verify directory integrity manifests.",
    )
    parser.add_argument("--version", action="version", version="dirguard 0.1.0")
    subparsers = parser.add_subparsers(dest="command")

    generate = subparsers.add_parser("generate", help="Generate an integrity manifest for a directory.")
    generate.add_argument("path", help="Directory to scan.")
    generate.add_argument("--out", default="manifest.json", help="Where to write the manifest (default: manifest.json).")
    generate.add_argument("--algorithm", default="sha256", choices=SUPPORTED_ALGORITHMS, help="Hash algorithm to use.")
    generate.add_argument("--ignore", action="append", default=[], help="Glob pattern to skip, repeatable.")
    generate.add_argument("--ignore-file", default=None, help="File of glob patterns to skip, one per line.")
    generate.add_argument("--follow-symlinks", action="store_true", help="Hash the target of symlinks instead of recording the link.")

    update = subparsers.add_parser(
        "update",
        help="Regenerate a manifest, reusing old hashes for files whose size and mtime have not changed.",
    )
    update.add_argument("path", help="Directory to scan.")
    update.add_argument("--out", default="manifest.json", help="Where to write the manifest (default: manifest.json).")
    update.add_argument("--baseline", default=None, help="Manifest to reuse hashes from (default: same as --out).")
    update.add_argument("--algorithm", default="sha256", choices=SUPPORTED_ALGORITHMS, help="Hash algorithm to use.")
    update.add_argument("--ignore", action="append", default=[], help="Glob pattern to skip, repeatable.")
    update.add_argument("--ignore-file", default=None, help="File of glob patterns to skip, one per line.")
    update.add_argument("--follow-symlinks", action="store_true", help="Hash the target of symlinks instead of recording the link.")

    verify = subparsers.add_parser("verify", help="Verify a directory against a manifest.")
    verify.add_argument("path", help="Directory to scan.")
    verify.add_argument("--manifest", default="manifest.json", help="Manifest to verify against (default: manifest.json).")
    verify.add_argument("--json", action="store_true", help="Print the report as JSON.")
    verify.add_argument("--quiet", action="store_true", help="Print nothing; rely on the exit code only.")

    diff = subparsers.add_parser("diff", help="Compare two saved manifests.")
    diff.add_argument("old", help="Older manifest.")
    diff.add_argument("new", help="Newer manifest.")
    diff.add_argument("--json", action="store_true", help="Print the diff as JSON.")
    diff.add_argument("--quiet", action="store_true", help="Print nothing; rely on the exit code only.")

    return parser


def read_manifest(path):
    # Returns (manifest, error_message) so callers can exit cleanly instead of
    # dumping a traceback when the file is missing or not valid JSON.
    if not os.path.isfile(path):
        return None, f"Manifest not found: {path}"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as err:
        return None, f"Manifest is not valid JSON: {path} ({err.msg} at line {err.lineno})"
    except OSError as err:
        return None, f"Could not read manifest {path}: {err}"
    if not isinstance(data, dict) or "files" not in data:
        return None, f"Manifest is missing its files section: {path}"
    return data, None


def run_generate(args):
    return run_generate_or_update(args, reuse_baseline=False)


def run_update(args):
    return run_generate_or_update(args, reuse_baseline=True)


def run_generate_or_update(args, reuse_baseline):
    if not os.path.isdir(args.path):
        print(f"Not a directory: {args.path}", file=sys.stderr)
        return 2

    patterns = load_ignore_patterns(args.ignore, args.ignore_file)

    # A manifest written inside the tree it describes would otherwise show up as
    # an added file on every later verification, so skip it by name.
    out_abs = os.path.abspath(args.out)
    root_abs = os.path.abspath(args.path)
    if out_abs.startswith(root_abs + os.sep):
        relative_out = os.path.relpath(out_abs, root_abs)
        patterns.append(relative_out)
        print(f"Note: {args.out} is inside {args.path}, skipping it during scans.")

    baseline = None
    if reuse_baseline:
        baseline_path = getattr(args, "baseline", None) or args.out
        baseline_data, error = read_manifest(baseline_path)
        if error:
            print(f"{error} Falling back to a full scan.", file=sys.stderr)
        else:
            baseline = baseline_data

    print(f"Scanning {args.path} with {args.algorithm}...")
    manifest = scan_directory(
        args.path,
        algorithm=args.algorithm,
        patterns=patterns,
        follow_symlinks=args.follow_symlinks,
        baseline=baseline,
    )
    # Write beside the target and swap it in, so an interrupted scan cannot
    # leave a half written manifest that later verifies as corrupt.
    temp_out = args.out + ".tmp"
    with open(temp_out, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    os.replace(temp_out, args.out)
    reused = manifest.get("reused_hashes", 0)
    reused_note = f", reused {reused} unchanged hash{'es' if reused != 1 else ''}" if reuse_baseline else ""
    print(f"Wrote {manifest['file_count']} entries to {args.out}{reused_note}")

    for entry in manifest["errors"]:
        print(f"Warning: could not read {entry['path']}: {entry['error']}", file=sys.stderr)
    return 0


def run_verify(args):
    if not os.path.isdir(args.path):
        if not args.quiet:
            print(f"Not a directory: {args.path}", file=sys.stderr)
        return 2

    # The manifest body is not used here, verify_directory reads it again.
    _, error = read_manifest(args.manifest)
    if error:
        if not args.quiet:
            print(error, file=sys.stderr)
        return 2

    report = verify_directory(args.path, args.manifest)
    if args.quiet:
        pass
    elif args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_report(report))
    # Exit code 1 signals tampering so this can gate a script or CI job.
    return 0 if report["clean"] else 1


def run_diff(args):
    for path in (args.old, args.new):
        _, error = read_manifest(path)
        if error:
            if not args.quiet:
                print(error, file=sys.stderr)
            return 2

    report = diff_manifests(args.old, args.new)
    if args.quiet:
        pass
    elif args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_report(report))
    return 0 if report["clean"] else 1


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate":
        return run_generate(args)
    if args.command == "update":
        return run_update(args)
    if args.command == "verify":
        return run_verify(args)
    if args.command == "diff":
        return run_diff(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
