#!/usr/bin/env python3
"""Validate the frozen v1.0.2 target, source-owner and include boundaries."""

from fnmatch import fnmatchcase
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"/]+/[^\"]+)"')
TARGET_RE = re.compile(r"CMakeFiles/([^/]+)\.dir/")
INITIAL_WAIVERS = {
    ("src/core/control_resolver.h", "dns/bootstrap.h"),
    ("src/core/core.c", "state/group_cache.h"),
    ("src/core/core.c", "frs/frs.h"),
    ("src/core/runtime.h", "group/url_test.h"),
    ("src/core/state.h", "state/group_cache.h"),
    ("src/dns/dns.h", "proxy/route/router.h"),
    ("src/dns/fakeip.h", "state/fakeip_store.h"),
    ("src/dns/fakeip.h", "state/snapshot.h"),
    ("src/dns/resolver.h", "proxy/session.h"),
}


def fail(message: str) -> None:
    raise SystemExit(f"structure boundary: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("compile_commands", type=Path)
    parser.add_argument("target_manifest", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument(
        "--self-test", choices=("illegal-include", "illegal-source")
    )
    return parser.parse_args()


def load_json(path: Path, description: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {description}: {exc}")


def validate_final_graph(policy: dict) -> list[str]:
    errors = []
    if policy.get("phase") not in {"migration", "final"}:
        errors.append("policy phase must be migration or final")
    targets = policy.get("final_targets")
    required = {
        "ftun_core", "ftun_tun", "ftun_dns", "ftun_proxy", "ftun_mesh",
        "ftun_app",
    }
    if not isinstance(targets, dict) or set(targets) != required:
        return ["final target set is not the frozen six-target graph"]

    for target, dependencies in targets.items():
        if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
            errors.append(f"invalid dependency list for {target}")
            continue
        for dependency in dependencies:
            if dependency not in targets:
                errors.append(f"{target} names unknown dependency {dependency}")
            if dependency == target:
                errors.append(f"{target} depends on itself")

    fixed_edges = {
        "ftun_core": [],
        "ftun_tun": ["ftun_core"],
        "ftun_dns": ["ftun_core"],
        "ftun_proxy": ["ftun_core", "ftun_tun"],
        "ftun_mesh": ["ftun_core", "ftun_tun"],
        "ftun_app": [
            "ftun_core", "ftun_tun", "ftun_dns", "ftun_proxy", "ftun_mesh",
        ],
    }
    if targets != fixed_edges:
        errors.append("final target edges differ from the frozen service graph")

    visiting = set()
    visited = set()

    def visit(target: str) -> None:
        if target in visiting:
            errors.append(f"final target graph contains a cycle at {target}")
            return
        if target in visited:
            return
        visiting.add(target)
        for dependency in targets.get(target, []):
            if dependency in targets:
                visit(dependency)
        visiting.remove(target)
        visited.add(target)

    for target in targets:
        visit(target)

    future = policy.get("future_targets")
    if future != ["ftun_mesh"]:
        errors.append("only ftun_mesh may be a future final target")
    final_paths = policy.get("final_path_targets")
    if not isinstance(final_paths, dict):
        errors.append("final path-to-target map is absent")
    else:
        expected_roots = {
            "src/app", "src/config", "src/core", "src/event", "src/internal",
            "src/network", "src/platform", "src/protocol", "src/tls",
            "src/transport", "src/util", "src/tun", "src/dns", "src/proxy",
            "src/mesh",
        }
        if set(final_paths) != expected_roots:
            errors.append("final path-to-target roots differ from the frozen map")
        unknown = set(final_paths.values()) - required
        if unknown:
            errors.append(f"final paths name unknown targets: {sorted(unknown)}")
    expected_forbidden_roots = {
        "src/api", "src/cli", "src/composition", "src/frs", "src/group",
        "src/inbound", "src/outbound", "src/route", "src/sniff", "src/state",
    }
    if set(policy.get("final_forbidden_roots", [])) != expected_forbidden_roots:
        errors.append("final forbidden legacy roots differ from the frozen set")
    forbidden_paths = policy.get("final_forbidden_paths")
    if not isinstance(forbidden_paths, list) or not forbidden_paths or (
        len(forbidden_paths) != len(set(forbidden_paths))
    ):
        errors.append("final forbidden path set is absent or invalid")
    elif any(
        not isinstance(path, str) or not path.startswith("src/")
        for path in forbidden_paths
    ):
        errors.append("final forbidden path set contains an invalid path")
    else:
        required_obsolete_paths = {
            "src/core/runtime.c", "src/core/runtime.h",
            "src/dns/dns.c", "src/dns/dns.h",
            "src/proxy/dns.c", "src/proxy/dns.h",
            "src/tun/tun.c", "src/tun/tun.h",
            "src/tun/lwip_adapter.c", "src/tun/lwip_adapter.h",
            "src/tun/lwip_port", "src/tun/udp_session.c",
            "src/tun/udp_session.h", "src/util/error.h",
        }
        missing_obsolete_paths = required_obsolete_paths - set(forbidden_paths)
        if missing_obsolete_paths:
            errors.append(
                "final forbidden path set lost frozen entries: "
                f"{sorted(missing_obsolete_paths)}"
            )
    return errors


def read_manifest(path: Path) -> dict[str, str]:
    manifest = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read target manifest: {exc}")
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or not name or name in manifest:
            fail(f"invalid target manifest line: {line}")
        manifest[name] = value
    return manifest


def read_owners(root: Path, commands: list[dict]) -> tuple[dict[str, str], list[str]]:
    owners = {}
    errors = []
    for entry in commands:
        try:
            source = Path(entry["file"]).resolve()
            relative = source.relative_to(root).as_posix()
        except (KeyError, OSError, ValueError):
            continue
        if not relative.startswith("src/") or not relative.endswith(".c"):
            continue
        match = TARGET_RE.search(entry.get("output", ""))
        if match is None:
            errors.append(f"compile command has no target owner: {relative}")
            continue
        target = match.group(1)
        if target.startswith("ftun-"):
            continue
        previous = owners.get(relative)
        if previous is not None and previous != target:
            errors.append(f"{relative} has product owners {previous} and {target}")
        owners[relative] = target
    return owners, errors


def validate_current_owners(
    root: Path, owners: dict[str, str], policy: dict, require_files: bool = True
) -> list[str]:
    errors = []
    allowed_targets = set(policy.get("current_product_targets", []))
    rules = policy.get("current_source_target_rules", [])
    for source, target in sorted(owners.items()):
        if require_files and not (root / source).is_file():
            errors.append(f"compiled product source is missing: {source}")
        if target not in allowed_targets:
            errors.append(f"{source} uses undeclared current target {target}")
            continue
        rule = next(
            (item for item in rules if fnmatchcase(source, item.get("pattern", ""))),
            None,
        )
        if rule is None:
            errors.append(f"compiled product source has no ownership rule: {source}")
        elif target not in rule.get("targets", []):
            errors.append(
                f"illegal source target: {source} is in {target}, allowed "
                f"{rule.get('targets', [])}"
            )
    return errors


def protected_layer(source: str, policy: dict):
    for name, layer in policy.get("protected_layers", {}).items():
        for root in layer.get("roots", []):
            if source == root or source.startswith(root + "/"):
                return name, layer
    return None, None


def observed_forbidden_includes(
    root: Path, policy: dict, injected: list[tuple[str, str]] | None = None
) -> tuple[set[tuple[str, str]], list[str]]:
    observed = set()
    errors = []
    paths = sorted(
        path for path in (root / "src").rglob("*")
        if path.suffix in {".c", ".h"}
    )
    pairs = []
    for path in paths:
        source = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot scan {source}: {exc}")
            continue
        for line in lines:
            match = INCLUDE_RE.match(line)
            if match:
                pairs.append((source, match.group(1)))
    pairs.extend(injected or [])
    for source, include in pairs:
        _, layer = protected_layer(source, policy)
        if layer is None:
            continue
        include_root = include.split("/", 1)[0]
        if include_root in set(layer.get("forbidden_include_roots", [])):
            observed.add((source, include))
    return observed, errors


def validate_includes(
    root: Path, policy: dict, injected: list[tuple[str, str]] | None = None
) -> list[str]:
    observed, errors = observed_forbidden_includes(root, policy, injected)
    waivers = policy.get("migration_include_waivers", [])
    waiver_pairs = []
    for waiver in waivers:
        pair = (waiver.get("source"), waiver.get("include"))
        if not all(isinstance(value, str) and value for value in pair):
            errors.append(f"invalid migration include waiver: {waiver!r}")
            continue
        remove_by = waiver.get("remove_by", "")
        if not re.fullmatch(r"S12-(?:00[3-9]|01[0-4])", remove_by):
            errors.append(f"waiver {pair!r} has invalid removal task {remove_by!r}")
        waiver_pairs.append(pair)
    if len(set(waiver_pairs)) != len(waiver_pairs):
        errors.append("migration include waivers contain duplicates")
    waiver_set = set(waiver_pairs)
    added_waivers = waiver_set - INITIAL_WAIVERS
    if added_waivers:
        errors.append(
            f"migration include waiver set expanded: {sorted(added_waivers)}"
        )
    for pair in sorted(observed - waiver_set):
        errors.append(f"forbidden business include: {pair[0]} -> {pair[1]}")
    for pair in sorted(waiver_set - observed):
        errors.append(f"stale migration include waiver: {pair[0]} -> {pair[1]}")
    if policy.get("phase") == "final" and waiver_set:
        errors.append("final phase retains migration include waivers")
    if policy.get("phase") == "final":
        for relative in policy.get("final_forbidden_roots", []):
            if (root / relative).exists():
                errors.append(f"final phase retains legacy source root: {relative}")
        for relative in policy.get("final_forbidden_paths", []):
            if (root / relative).exists():
                errors.append(f"final phase retains obsolete source path: {relative}")
    return errors


def validate_final_tree(root: Path, policy: dict) -> list[str]:
    if policy.get("phase") != "final":
        return []
    errors = []
    final_roots = tuple(sorted(policy.get("final_path_targets", {})))
    hashes: dict[str, list[str]] = {}
    for path in sorted((root / "src").rglob("*")):
        if not path.is_file() or path.suffix not in {".c", ".h"}:
            continue
        relative = path.relative_to(root).as_posix()
        if not any(
            relative == source_root or relative.startswith(source_root + "/")
            for source_root in final_roots
        ):
            errors.append(f"source is outside the final roots: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes.setdefault(digest, []).append(relative)
        if path.suffix != ".h":
            continue
        text = re.sub(
            r"/\*.*?\*/|//[^\n]*", "", path.read_text(encoding="utf-8"),
            flags=re.DOTALL,
        )
        guard = None
        significant = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = re.fullmatch(r"#ifndef\s+([A-Za-z_][A-Za-z0-9_]*)", stripped)
            if match and guard is None:
                guard = match.group(1)
                continue
            if guard is not None and stripped == f"#define {guard}":
                continue
            if stripped == "#endif":
                continue
            significant.append(stripped)
        if significant and all(line.startswith("#include ") for line in significant):
            errors.append(f"final tree retains forwarding header: {relative}")
    for duplicates in hashes.values():
        if len(duplicates) > 1:
            errors.append(f"final tree contains duplicate source bodies: {duplicates}")

    scan_paths = [root / "CMakeLists.txt"]
    for directory in (root / "cmake", root / "src", root / "tests"):
        scan_paths.extend(
            path for path in directory.rglob("*")
            if path.is_file() and path.suffix in {
                ".c", ".h", ".cmake", ".py", ".sh", ".txt"
            }
        )
    exempt = {
        (root / "cmake/ftun-layer-policy.json").resolve(),
        (root / "tests/build_target_boundaries.py").resolve(),
        (root / "tests/structure_boundaries.py").resolve(),
    }
    obsolete = policy.get("final_forbidden_paths", [])
    for path in scan_paths:
        if path.resolve() in exempt:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for old_path in obsolete:
            if old_path in text:
                errors.append(
                    f"active build/source/test file references obsolete path: "
                    f"{path.relative_to(root).as_posix()} -> {old_path}"
                )
    return errors


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    policy = load_json(args.policy, "layer policy")
    commands = load_json(args.compile_commands, "compile commands")
    if not isinstance(policy, dict) or policy.get("schema") != "ftun-layer-policy-v1":
        fail("invalid layer policy schema")
    if not isinstance(commands, list):
        fail("compile_commands.json is not an array")

    errors = validate_final_graph(policy)
    manifest = read_manifest(args.target_manifest)
    for name, expected in policy.get("current_manifest", {}).items():
        if expected == "OPTIONAL":
            if manifest.get(name) not in {"OFF", f"ftun_{name}"}:
                errors.append(
                    f"target manifest maps optional {name} to "
                    f"{manifest.get(name)!r}"
                )
            continue
        if manifest.get(name) != expected:
            errors.append(
                f"target manifest maps {name} to {manifest.get(name)!r}, expected "
                f"{expected!r}"
            )
    owners, owner_errors = read_owners(root, commands)
    errors.extend(owner_errors)
    errors.extend(validate_current_owners(root, owners, policy))
    errors.extend(validate_includes(root, policy))
    errors.extend(validate_final_tree(root, policy))
    if errors:
        fail("; ".join(errors))

    if args.self_test == "illegal-source":
        injected = dict(owners)
        injected["src/proxy/injected_illegal.c"] = "ftun_core"
        injected_errors = validate_current_owners(
            root, injected, policy, require_files=False
        )
        if not any("illegal source target" in error for error in injected_errors):
            fail("illegal source-path injection was not rejected")
        print("structure boundary self-test: illegal source path rejected")
        return 0

    if args.self_test == "illegal-include":
        injected_errors = validate_includes(
            root,
            policy,
            [("src/network/view.c", "proxy/runtime.h")],
        )
        if not any("forbidden business include" in error for error in injected_errors):
            fail("illegal include injection was not rejected")
        print("structure boundary self-test: illegal include rejected")
        return 0

    print(
        "structure boundary: ok; final graph 6 targets; "
        "current sources owned; migration include waivers "
        f"{len(policy.get('migration_include_waivers', []))}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
