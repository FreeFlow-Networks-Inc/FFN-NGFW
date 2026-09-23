#!/usr/bin/env python3
"""Catalog an imported Linux build workspace without publishing or altering inputs."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


CATEGORIES = {
    "toolchains": ("toolchain", "sdk", "gcc"),
    "hardware": ("bcm", "bde", "fe100", "fpga", "pcidma", "kctl", "driver"),
    "kernels": ("kbuild", "dpkernel", "vmlinux", "kernel", "dpbuild"),
    "references": ("sysroot", "panos", "maint-full", "panrepo", "rpmx"),
    "networking": ("fwd", "transport", "conntrack", "nat", "security", "policy", "frr", "ovs", "ovn", "zt-"),
    "images": ("image", "reimage", "rootfs", "initramfs", "debian", "ffn-build", "modules"),
}


def category(name):
    for group, fragments in CATEGORIES.items():
        if any(s in name.lower() for s in fragments):
            return group
    return "utilities"


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


def initialize(root):
    root.mkdir(parents=True, exist_ok=True)
    for name in ("sources", "work", "artifacts", "published", "config", "logs", "bin"):
        (root / name).mkdir(exist_ok=True)
    for name in ("private", "private/imports", "private/imports/vm", "private/catalog", "private/tools"):
        p = root / name
        p.mkdir(exist_ok=True)
        p.chmod(0o700)


def compiler_paths(root):
    """Search build inputs only; do not mistake target rootfs programs for host tools."""
    imports = root / "private/imports/vm"
    patterns = (
        "home-tools/toolchains/*/*/bin/*gcc",
        "clones/fwdport/gcc-*/*/bin/*gcc",
        "clones/openwrt-toolchain/*/bin/*gcc",
        "clones/sdk51/OCTEON-SDK/tools*/bin/*gcc",
        "clones/octeon-sdk-all/**/bin/*gcc",
    )
    found = {}
    for pattern in patterns:
        for p in imports.glob(pattern):
            # Broken/absolute links are cataloged but never silently rewritten.
            if p.is_file() or p.is_symlink():
                key = str(p.relative_to(imports))
                found[key] = {"id": key, "path": str(p), "available": p.is_file(),
                              "symlink": os.readlink(p) if p.is_symlink() else None}
    return list(found.values())


def catalog(root):
    initialize(root)
    imports = root / "private/imports/vm"
    entries = []
    for source in sorted(imports.iterdir()):
        if not source.is_dir() or source.is_symlink():
            continue
        for p in sorted(source.iterdir()):
            group = category(p.name)
            alias = root / "private/tools" / group / source.name / p.name
            alias.parent.mkdir(parents=True, exist_ok=True)
            relative = os.path.relpath(p, alias.parent)
            if alias.is_symlink():
                if os.readlink(alias) != relative:
                    raise ValueError("Refusing to replace unrelated catalog link: " + str(alias))
            elif alias.exists():
                raise ValueError("Refusing to overwrite existing catalog entry: " + str(alias))
            else:
                alias.symlink_to(relative, target_is_directory=p.is_dir())
            entries.append({"name": p.name, "origin": source.name, "category": group,
                            "path": str(p), "shortcut": str(alias),
                            "symlink": os.readlink(p) if p.is_symlink() else None})
    state = root / "private/migration/state.json"
    report = {"schema": 1, "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "root": str(root), "migration": json.loads(state.read_text()) if state.exists() else None,
              "entries": entries, "compilers": compiler_paths(root)}
    atomic_json(root / "private/catalog/tools.json", report)
    lines = ["# Imported build tools", "", "Original relative layouts are preserved under `private/imports/vm/`.",
             "Category links below point to those copies. Imported reference data is not release input by default.", ""]
    for group in sorted(set(e["category"] for e in entries)):
        lines += ["## " + group, ""]
        lines += ["- `" + e["origin"] + "/" + e["name"] + "`" for e in entries if e["category"] == group]
        lines += [""]
    (root / "private/catalog/TOOLS.md").write_text("\n".join(lines))
    print(json.dumps({"catalog": str(root / "private/catalog/tools.json"), "entries": len(entries),
                      "compiler_candidates": len(report["compilers"]), "migration": report["migration"]}, indent=2))


def probe_compiler(compiler, work):
    """Compile an object only; never execute target code or need libc/sysroot."""
    result = dict(compiler)
    try:
        version = subprocess.run([compiler["path"], "--version"], capture_output=True, text=True, timeout=15, check=True)
        machine = subprocess.run([compiler["path"], "-dumpmachine"], capture_output=True, text=True, timeout=15, check=True)
        result.update(version=version.stdout.splitlines()[0], target=machine.stdout.strip())
        with tempfile.TemporaryDirectory(prefix="compiler-probe-", dir=work) as tmp:
            src, obj = Path(tmp) / "probe.c", Path(tmp) / "probe.o"
            src.write_text("unsigned long ffn_build_probe(unsigned long value) { return value + 1; }\n")
            cmd = [compiler["path"], "-c", "-ffreestanding", "-fno-stack-protector"]
            if "mips" in result["target"]:
                cmd += ["-EB", "-mabi=64"]
            subprocess.run(cmd + [str(src), "-o", str(obj)], capture_output=True, text=True, timeout=30, check=True)
            header = obj.read_bytes()[:20]
            if header[:4] != b"\x7fELF":
                raise ValueError("Compiler did not produce ELF")
            result.update(elf_bits=64 if header[4] == 2 else 32, byte_order="big" if header[5] == 2 else "little")
            if "mips" in result["target"] and (header[4:6] != b"\x02\x02" or int.from_bytes(header[18:20], "big") != 8):
                raise ValueError("MIPS compiler did not produce MIPS64 big-endian ELF")
        result["status"] = "working"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(status="unavailable", error=str(exc),
                      detail=(getattr(exc, "stderr", "") or "")[-2000:])
    return result


def doctor(root):
    initialize(root)
    compilers = [probe_compiler(c, root / "work") for c in compiler_paths(root)]
    commands = {n: shutil.which(n) for n in ("git", "make", "gcc", "python3", "rsync", "debootstrap", "qemu-img", "zstd", "openssl", "bison", "flex", "bc")}
    report = {"schema": 1, "commands": commands, "compilers": compilers,
              "missing_commands": [n for n, p in commands.items() if not p],
              "note": "Object compilation proves tool relocation and target format, not a bootable or qualified CP/DP image."}
    atomic_json(root / "private/catalog/doctor.json", report)
    print(json.dumps(report, indent=2))


def environment(root, toolchain):
    report = json.loads((root / "private/catalog/doctor.json").read_text())
    matches = [c for c in report["compilers"] if c["id"] == toolchain and c["status"] == "working"]
    if len(matches) != 1:
        raise ValueError("Select one working compiler ID from private/catalog/doctor.json")
    compiler = matches[0]["path"]
    target = matches[0]["target"]
    arch = next((arch for prefix, arch in (("mips", "mips"), ("aarch64", "arm64"),
                ("arm", "arm"), ("powerpc", "powerpc"), ("riscv", "riscv"),
                ("x86_64", "x86"), ("i686", "x86"), ("i386", "x86"))
                if target.startswith(prefix)), None)
    if arch is None:
        raise ValueError("No kernel architecture mapping for compiler target: " + target)
    for name, value in {"FFN_BUILD_ROOT": str(root), "ARCH": arch, "CROSS_COMPILE": compiler[:-3]}.items():
        print("export " + name + "=" + shlex.quote(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="New dedicated build workspace")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("catalog", help="Create categorized shortcuts and a machine-readable inventory")
    sub.add_parser("doctor", help="Check prerequisites and cross-compile temporary ELF objects")
    env = sub.add_parser("env", help="Print shell exports for an explicitly selected working toolchain")
    env.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    if root == Path("/") or not root.is_absolute():
        parser.error("Choose a dedicated absolute workspace directory")
    try:
        if args.command == "catalog": catalog(root)
        elif args.command == "doctor": doctor(root)
        else: environment(root, args.toolchain)
    except (OSError, ValueError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
