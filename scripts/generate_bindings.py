#!/usr/bin/env python3
"""Write the Python and TypeScript bindings from schema/identity.v1.json.

The language files in scripts/binding_templates are the generator input.
schema/identity.v1.json is copied beside each binding. `--check` fails when
bindings/ is not the current output.
"""

import filecmp
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "identity.v1.json"
TEMPLATES = ROOT / "scripts" / "binding_templates"
OUTPUTS = {
    "identity_schema.py": ROOT / "bindings" / "python" / "identity_schema.py",
    "package.json": ROOT / "bindings" / "typescript" / "package.json",
    "check.ts": ROOT / "bindings" / "typescript" / "check.ts",
}


def build(directory: pathlib.Path) -> None:
    python = directory / "python"
    typescript = directory / "typescript"
    python.mkdir(parents=True)
    typescript.mkdir(parents=True)
    shutil.copyfile(TEMPLATES / "identity_schema.py", python / "identity_schema.py")
    shutil.copyfile(SCHEMA, python / "identity.v1.json")
    shutil.copyfile(TEMPLATES / "package.json", typescript / "package.json")
    shutil.copyfile(TEMPLATES / "check.ts", typescript / "check.ts")
    shutil.copyfile(SCHEMA, typescript / "schema.json")


def check() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        fresh = pathlib.Path(tmp)
        build(fresh)
        failed = 0
        for kind in ("python", "typescript"):
            got = ROOT / "bindings" / kind
            expected = fresh / kind
            names = sorted(path.name for path in expected.iterdir())
            present = sorted(path.name for path in got.iterdir() if path.name != "node_modules" and path.name != "bun.lock")
            if names != present:
                print(f"bindings/{kind} files {present} != generated {names}")
                failed = 1
                continue
            for name in names:
                if not filecmp.cmp(expected / name, got / name, shallow=False):
                    print(f"bindings/{kind}/{name} is stale; run scripts/generate_bindings.py")
                    failed = 1
        if failed:
            return 1
    print("bindings current")
    return 0


def main() -> int:
    if "--check" in sys.argv:
        return check()
    out = ROOT / "bindings"
    with tempfile.TemporaryDirectory() as tmp:
        fresh = pathlib.Path(tmp) / "bindings"
        build(fresh)
        if out.exists():
            for kind in ("python", "typescript"):
                dest = out / kind
                dest.mkdir(parents=True, exist_ok=True)
                for path in (fresh / kind).iterdir():
                    shutil.copyfile(path, dest / path.name)
        else:
            shutil.copytree(fresh, out)
    print("wrote bindings/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
