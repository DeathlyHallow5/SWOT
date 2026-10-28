"""Install the official nuclei-templates collection at a pinned version.

Shallow-clones projectdiscovery/nuclei-templates into tools/nuclei-templates so
the "Official" Nuclei source becomes available. Re-running updates to the pin.

    python scripts/install_nuclei_templates.py            # default pin
    python scripts/install_nuclei_templates.py v10.2.9    # a specific tag
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
DEFAULT_TAG = "v10.5.1"
DEST = Path(__file__).resolve().parents[1] / "tools" / "nuclei-templates"


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TAG
    if shutil.which("git") is None:
        print("git is required to install nuclei-templates.", file=sys.stderr)
        return 1
    if DEST.exists():
        print(f"Removing existing {DEST}")
        shutil.rmtree(DEST, ignore_errors=True)
    DEST.parent.mkdir(parents=True, exist_ok=True)
    print(f"Cloning {REPO} @ {tag} (shallow) …")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", tag, REPO, str(DEST)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        return result.returncode
    # Drop the .git directory; only the templates are needed.
    shutil.rmtree(DEST / ".git", ignore_errors=True)
    count = sum(1 for _ in DEST.rglob("*.yaml"))
    print(f"Installed {count} templates into {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
