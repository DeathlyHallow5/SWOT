"""Install pinned ProjectDiscovery releases, verifying SHA-256 checksums.

Usage: python scripts/install_tools.py [--dest tools/bin] [--only httpx dnsx]
No Go toolchain or package installation is needed.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import io
import json
import os
import platform
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = json.loads((ROOT / "tools/versions.json").read_text(encoding="utf-8-sig"))


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "SWOT-tool-installer/2.1"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


def install(name: str, dest: Path, system: str, arch: str) -> None:
    version = VERSIONS[name]
    asset = f"{name}_{version}_{system}_{arch}.zip"
    base = f"https://github.com/projectdiscovery/{name}/releases/download/v{version}"
    checksum_file = {"katana": f"katana-{version}-checksums.txt", "naabu": "naabu-checksums.txt"}.get(name, f"{name}_{version}_checksums.txt")
    sums = fetch(f"{base}/{checksum_file}").decode()
    expected = next((line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip("*") == asset), None)
    if expected is None:
        raise RuntimeError(f"No published checksum for {asset}")
    data = fetch(f"{base}/{asset}")
    if hashlib.sha256(data).hexdigest().lower() != expected.lower():
        raise RuntimeError(f"Checksum mismatch: {asset}")
    suffix = ".exe" if system == "windows" else ""
    output = dest / (("pd-httpx" if name == "httpx" else name) + suffix)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        binary = next(n for n in archive.namelist() if Path(n).name == name + suffix)
        temporary = output.with_suffix(output.suffix + ".new")
        temporary.write_bytes(archive.read(binary))
        temporary.chmod(0o755)
        temporary.replace(output)
        for filename in archive.namelist():
            if Path(filename).name.lower().startswith("license"):
                licenses = dest / "licenses"
                licenses.mkdir(exist_ok=True)
                (licenses / f"{name}.txt").write_bytes(archive.read(filename))
    print(f"Installed {name} {version} (SHA-256 verified)", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, default=ROOT / "tools/bin")
    parser.add_argument("--only", nargs="+", choices=list(VERSIONS))
    args = parser.parse_args()
    system = platform.system().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if system not in ("linux", "windows", "darwin") or arch is None:
        raise SystemExit(f"Unsupported platform: {system}/{platform.machine()}")
    args.dest.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(install, name, args.dest, system, arch) for name in (args.only or VERSIONS)]
        for future in futures:
            future.result()


if __name__ == "__main__":
    main()
