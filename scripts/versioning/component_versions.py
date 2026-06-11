#!/usr/bin/env python3
"""Manage independent component versions for the repository.

The source of truth for a component version is its Cargo.toml package version.
This helper keeps the matching Cargo.lock package entry in sync and gives CI a
dependency-free way to detect which components changed in a merged PR.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / ".github" / "versioning" / "components.json"
VERSION_RE = re.compile(r'^version\s*=\s*"(?P<version>\d+\.\d+\.\d+)"\s*$')


@dataclass(frozen=True)
class Component:
    key: str
    package: str
    manifest: Path
    lockfile: Path
    tag_prefix: str
    paths: tuple[str, ...]


def load_config(path: Path) -> tuple[int, dict[str, Component]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    project_major = int(raw["project_major"])
    components = {}
    for key, data in raw["components"].items():
        components[key] = Component(
            key=key,
            package=data["package"],
            manifest=REPO_ROOT / data["manifest"],
            lockfile=REPO_ROOT / data["lockfile"],
            tag_prefix=data["tag_prefix"],
            paths=tuple(data["paths"]),
        )
    return project_major, components


def read_component_version(component: Component) -> str:
    in_package = False
    for line in component.manifest.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if stripped.startswith("[") and stripped != "[package]":
            in_package = False
        if in_package:
            match = VERSION_RE.match(stripped)
            if match:
                return match.group("version")
    raise ValueError(f"package version not found in {component.manifest}")


def parse_version(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"expected semantic version X.Y.Z, got {version}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def replace_manifest_version(component: Component, new_version: str) -> None:
    lines = component.manifest.read_text(encoding="utf-8").splitlines()
    in_package = False
    replaced = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if stripped.startswith("[") and stripped != "[package]":
            in_package = False
        if in_package and VERSION_RE.match(stripped):
            prefix = line[: len(line) - len(line.lstrip())]
            lines[index] = f'{prefix}version = "{new_version}"'
            replaced = True
            break
    if not replaced:
        raise ValueError(f"package version not found in {component.manifest}")
    component.manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def replace_lockfile_version(component: Component, new_version: str) -> None:
    lines = component.lockfile.read_text(encoding="utf-8").splitlines()
    in_package_block = False
    matching_package = False
    replaced = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[[package]]":
            in_package_block = True
            matching_package = False
            continue
        if in_package_block and stripped.startswith("name = "):
            matching_package = stripped == f'name = "{component.package}"'
            continue
        if in_package_block and matching_package and VERSION_RE.match(stripped):
            prefix = line[: len(line) - len(line.lstrip())]
            lines[index] = f'{prefix}version = "{new_version}"'
            replaced = True
            break

    if not replaced:
        raise ValueError(
            f"package {component.package} version not found in {component.lockfile}"
        )
    component.lockfile.write_text("\n".join(lines) + "\n", encoding="utf-8")


def changed_files_from_file(path: Path) -> list[str]:
    return [
        line.strip().replace("\\", "/")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def component_matches_path(component: Component, changed_path: str) -> bool:
    for pattern in component.paths:
        if fnmatch.fnmatch(changed_path, pattern):
            return True
    return False


def detect_changed_components(
    components: dict[str, Component],
    changed_files: Iterable[str],
) -> list[str]:
    changed = []
    for key, component in components.items():
        if any(component_matches_path(component, path) for path in changed_files):
            changed.append(key)
    return changed


def git_diff_contains_package_version_change(
    component: Component,
    base_ref: str,
    head_ref: str,
) -> bool:
    manifest = component.manifest.relative_to(REPO_ROOT).as_posix()
    result = subprocess.run(
        ["git", "diff", "--unified=0", base_ref, head_ref, "--", manifest],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    for line in result.stdout.splitlines():
        if line.startswith(("+version = ", "-version = ")):
            return True
    return False


def github_output(values: dict[str, str]) -> None:
    output_name = os.environ.get("GITHUB_OUTPUT")
    if output_name:
        output_path = Path(output_name)
        with output_path.open("a", encoding="utf-8") as handle:
            for key, value in values.items():
                handle.write(f"{key}={value}\n")


def cmd_changed(args: argparse.Namespace) -> int:
    _, components = load_config(args.config)
    changed_files = changed_files_from_file(args.changed_files)
    changed = detect_changed_components(components, changed_files)
    manually_versioned = []

    if args.diff_base and args.diff_head:
        manually_versioned = [
            key
            for key in changed
            if git_diff_contains_package_version_change(
                components[key], args.diff_base, args.diff_head
            )
        ]

    auto_bump = [key for key in changed if key not in manually_versioned]
    values = {
        "components": ",".join(changed),
        "auto_bump_components": ",".join(auto_bump),
        "manually_versioned_components": ",".join(manually_versioned),
    }
    github_output(values)
    print(json.dumps(values, indent=2, sort_keys=True))
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    _, components = load_config(args.config)
    component = components[args.component]
    version = read_component_version(component)
    tag = f"{component.tag_prefix}{version}"
    values = {
        "version": version,
        "tag": tag,
        "tag_prefix": component.tag_prefix,
    }
    print(values[args.field])
    github_output(
        values
    )
    return 0


def cmd_bump(args: argparse.Namespace) -> int:
    project_major, components = load_config(args.config)
    component = components[args.component]
    current = read_component_version(component)
    major, minor, patch = parse_version(current)
    if major != project_major:
        raise ValueError(
            f"{component.key} major version {major} does not match project_major "
            f"{project_major}"
        )

    new_version = f"{major}.{minor}.{patch + 1}"
    replace_manifest_version(component, new_version)
    replace_lockfile_version(component, new_version)
    print(new_version)
    github_output(
        {
            "version": new_version,
            "tag": f"{component.tag_prefix}{new_version}",
        }
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    project_major, components = load_config(args.config)
    errors = []

    for component in components.values():
        manifest_version = read_component_version(component)
        major, _, _ = parse_version(manifest_version)
        if major != project_major:
            errors.append(
                f"{component.key}: manifest major {major} does not match "
                f"project_major {project_major}"
            )

        lock_text = component.lockfile.read_text(encoding="utf-8")
        expected = f'name = "{component.package}"\nversion = "{manifest_version}"'
        if expected not in lock_text:
            errors.append(
                f"{component.key}: {component.lockfile.relative_to(REPO_ROOT)} "
                f"is not synced to version {manifest_version}"
            )

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print("component versions are valid")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Path to component versioning config",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    changed = subparsers.add_parser("changed")
    changed.add_argument("--changed-files", type=Path, required=True)
    changed.add_argument("--diff-base")
    changed.add_argument("--diff-head")
    changed.set_defaults(func=cmd_changed)

    get = subparsers.add_parser("get")
    get.add_argument("--component", required=True)
    get.add_argument(
        "--field",
        choices=("version", "tag", "tag_prefix"),
        default="version",
    )
    get.set_defaults(func=cmd_get)

    bump = subparsers.add_parser("bump")
    bump.add_argument("--component", required=True)
    bump.set_defaults(func=cmd_bump)

    validate = subparsers.add_parser("validate")
    validate.set_defaults(func=cmd_validate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
