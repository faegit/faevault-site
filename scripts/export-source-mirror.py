"""Export an audited, allowlisted source snapshot; never copy repository history."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

ANDROID_PATTERNS = (
    "app/src/main/java/com/vault/*.kt", "app/src/test/java/com/vault/*.kt",
    "app/src/androidTest/java/com/vault/*.kt", "app/src/debug/java/com/vault/*.kt",
    "app/src/main/res/values*/*.xml", "app/src/main/res/xml/*.xml",
    "app/src/test/resources/hardcoded_chinese_baseline.txt",
    "spec/*.md", "spec/*.json",
)
ANDROID_EXACT = {
    "app/src/main/AndroidManifest.xml", "app/src/debug/AndroidManifest.xml",
    "build.gradle.kts", "settings.gradle.kts", "app/build.gradle.kts",
    "app/proguard-rules.pro", "app/lint.xml", "THIRD_PARTY_LICENSES.md",
    "gradle/wrapper/gradle-wrapper.properties", "gradle/verification-metadata.xml",
    *(f"spec/interop/pmv_next/v1/blobs/{name}.pmv" for name in (
        "store_android_from_pc_seq2", "store_android_seq1",
        "store_pc_from_android_seq2", "store_pc_seq1")),
}
PC_PATTERNS = (
    "core/*.py", "ui/*.py", "tests/*.py", "tests/*.js", "tests/*.mjs",
    "browser_extension/*.js", "browser_extension/*.json",
    "browser_extension/*.html", "browser_extension/*.css", "spec/*.md", "spec/*.json",
    *(f"native/passkey_provider/*.{ext}" for ext in (
        "cpp", "h", "idl", "xaml", "vcxproj", "filters", "sln", "manifest", "appxmanifest")),
)
PC_EXACT = {
    "__main__.py", "browser_host.py", "pyproject.toml", "uv.lock", ".python-version",
    "native/passkey_provider/app/packages.config",
    "native/passkey_provider/MICROSOFT_SAMPLE_LICENSE.txt",
    "native/passkey_provider/README.md",
}
BLOCKED_COMPONENTS = {
    ".git", ".venv", "node_modules", "build", "dist", "obj", "bin", "packages",
    "__pycache__", ".signing", "keystore", "security_audit", "redteam_sandbox",
    "assets", "Assets", "icons", "data",
}
SECRET_PATTERNS = (
    ("GitHub credential", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("AWS access identifier", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private key PEM", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
SYNTHETIC_PEM_PATHS = {"app/src/test/java/com/vault/DemoVaultGenerator.kt"}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def permitted(platform: str, relative: str) -> bool:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or BLOCKED_COMPONENTS.intersection(path.parts):
        return False
    exact, patterns = (ANDROID_EXACT, ANDROID_PATTERNS) if platform == "android" else (PC_EXACT, PC_PATTERNS)
    return relative in exact or any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)


def candidate_files(root: Path, platform: str) -> list[str]:
    result = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ).decode("utf-8")
    return sorted({name for name in result.split("\0") if name and permitted(platform, name)})


def inspect_bytes(relative: str, value: bytes) -> None:
    for label, pattern in SECRET_PATTERNS:
        if label == "private key PEM" and relative in SYNTHETIC_PEM_PATHS:
            # The audited generator explicitly marks all data as fictional.
            if b"DEMO" in value:
                continue
        if pattern.search(value):
            raise ValueError(f"Publication blocked: {label} detected in {relative}; value withheld")


def source_version(root: Path, platform: str) -> str:
    text = (root / ("app/build.gradle.kts" if platform == "android" else "pyproject.toml")).read_text(encoding="utf-8")
    expression = r'versionName\s*=\s*"([^"]+)"' if platform == "android" else r'^version\s*=\s*"([^"]+)"'
    return re.search(expression, text, re.MULTILINE).group(1)


def archive(directory: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for file in sorted(directory.rglob("*")):
            if file.is_file():
                info = zipfile.ZipInfo(file.relative_to(directory).as_posix(), (2026, 10, 5, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                output.writestr(info, file.read_bytes())


def export(roots: dict[str, Path], site: Path, date: str) -> dict:
    mirror, downloads = site / "source-mirror", site / "public/source"
    downloads.mkdir(parents=True, exist_ok=True)
    license_bytes = (mirror / "LICENSE").read_bytes()
    notices = (mirror / "NOTICE").read_bytes()
    report = {"schema": 1, "snapshot_date": date, "license": "Apache-2.0", "platforms": {}}
    for platform, root in roots.items():
        destination = mirror / platform
        # Existing outputs are deliberately not deleted. Unexpected files fail validation.
        destination.mkdir(parents=True, exist_ok=True)
        files, original_hashes = [], {}
        for relative in candidate_files(root, platform):
            source = root / relative
            if source.is_symlink() or root not in source.resolve().parents:
                raise ValueError(f"Unsafe source path: {relative}")
            value = source.read_bytes()
            inspect_bytes(relative, value)
            original_hashes[relative] = digest(value)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            files.append({"path": relative, "bytes": len(value), "sha256": digest(value), "kind": "source"})
        if platform == "pc":
            # PC tests support this location via VAULT_SHARED_SPEC_DIR=./spec.
            for relative in candidate_files(roots["android"], "android"):
                if not relative.startswith("spec/"):
                    continue
                value = (roots["android"] / relative).read_bytes()
                inspect_bytes(relative, value)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(value)
                files = [item for item in files if item["path"] != relative]
                files.append({"path": relative, "bytes": len(value), "sha256": digest(value), "kind": "shared-fixture"})
        for name, value in (("LICENSE", license_bytes), ("NOTICE", notices), ("OPEN_SOURCE_REVIEW.md", (mirror / "OPEN_SOURCE_REVIEW.md").read_bytes())):
            (destination / name).write_bytes(value)
            files.append({"path": name, "bytes": len(value), "sha256": digest(value), "kind": "publication-notice"})
        readme = (
            f"# FAEVault {platform} source-review snapshot\n\n"
            f"Snapshot date: {date}. Application version: {source_version(root, platform)}.\n\n"
            "Original FAEVault source in this snapshot is provided under Apache-2.0.\n"
            "Retained upstream notices and Microsoft sample files keep their own licenses.\n"
            "See LICENSE, NOTICE and OPEN_SOURCE_REVIEW.md for the selection policy.\n\n"
            "This is a reviewed source snapshot, not the complete private repository or a\n"
            "reproducible signed application distribution. Signing keys, user data, private\n"
            "audit evidence, third-party binary bundles, icons, fonts, dictionaries and other\n"
            "assets with incomplete provenance are intentionally omitted. UI code references\n"
            "some omitted assets; do not expect a full app build or every UI test to run.\n\n"
            "Cryptographic test keys and passwords in the included fixtures are synthetic\n"
            "public test data. They must never be used as production credentials.\n\n"
            + ("PC shared-vector tests can use VAULT_SHARED_SPEC_DIR=./spec. Python dependencies\n"
               "are declared in pyproject.toml and uv.lock; Qt and other libraries keep their\n"
               "upstream licenses and are not bundled here.\n" if platform == "pc" else
               "Dependency and build declarations are included for review. Local Gradle\n"
               "properties, the wrapper binary and third-party packaged assets are omitted.\n")
        ).encode("utf-8")
        (destination / "README.md").write_bytes(readme)
        files.append({"path": "README.md", "bytes": len(readme), "sha256": digest(readme), "kind": "publication-notice"})
        for relative, expected in original_hashes.items():
            if digest((root / relative).read_bytes()) != expected:
                raise ValueError(f"Source changed during export: {relative}; retry the snapshot")
        manifest = {"schema": 1, "snapshot_date": date, "license": "Apache-2.0", "platform": platform,
                    "version": source_version(root, platform),
                    "source_commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
                    "working_tree_snapshot": True, "files": sorted(files, key=lambda item: item["path"])}
        (destination / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        zip_path = downloads / f"faevault-{platform}-source.zip"
        archive(destination, zip_path)
        report["platforms"][platform] = {
            "version": manifest["version"], "file_count": len(files) + 1,
            "bytes": sum(item["bytes"] for item in files) + (destination / "MANIFEST.json").stat().st_size,
            "archive_bytes": zip_path.stat().st_size, "archive_sha256": digest(zip_path.read_bytes()),
            "source_commit": manifest["source_commit"],
        }
    (downloads / "snapshot.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (downloads / "SHA256SUMS.txt").write_text("".join(
        f"{data['archive_sha256']}  faevault-{name}-source.zip\n" for name, data in report["platforms"].items()
    ), encoding="utf-8")
    return report


def validate(site: Path) -> None:
    report = json.loads((site / "public/source/snapshot.json").read_text(encoding="utf-8"))
    for platform, metadata in report["platforms"].items():
        root = site / "source-mirror" / platform
        manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
        expected = {item["path"] for item in manifest["files"]} | {"MANIFEST.json"}
        actual = {file.relative_to(root).as_posix() for file in root.rglob("*") if file.is_file()}
        if expected != actual:
            raise ValueError(f"Unexpected/missing files in {platform} snapshot")
        for item in manifest["files"]:
            allowed_notice = item["kind"] == "publication-notice" and item["path"] in {"LICENSE", "NOTICE", "README.md", "OPEN_SOURCE_REVIEW.md"}
            allowed_fixture = item["kind"] == "shared-fixture" and platform == "pc" and item["path"].startswith("spec/") and permitted("android", item["path"])
            if not (allowed_notice or allowed_fixture or (item["kind"] == "source" and permitted(platform, item["path"]))):
                raise ValueError(f"Non-allowlisted published path: {item['path']}")
            value = (root / item["path"]).read_bytes()
            inspect_bytes(item["path"], value)
            if digest(value) != item["sha256"]:
                raise ValueError(f"Hash mismatch: {item['path']}")
        archive_path = site / "public/source" / f"faevault-{platform}-source.zip"
        if digest(archive_path.read_bytes()) != metadata["archive_sha256"]:
            raise ValueError(f"Archive hash mismatch for {platform}")
        with zipfile.ZipFile(archive_path) as archive_file:
            if set(archive_file.namelist()) != expected:
                raise ValueError(f"Archive inventory mismatch for {platform}")
            for relative in expected:
                if archive_file.read(relative) != (root / relative).read_bytes():
                    raise ValueError(f"Archive content mismatch: {relative}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--android", type=Path)
    parser.add_argument("--pc", type=Path)
    parser.add_argument("--site", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--date", default="2026-10-05")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    site = args.site.resolve()
    if args.check:
        validate(site)
        print("Source mirror inventories, allowlists, secret checks and archive hashes verified")
        return
    if not args.android or not args.pc:
        parser.error("--android and --pc are required to export")
    result = export({"android": args.android.resolve(), "pc": args.pc.resolve()}, site, args.date)
    validate(site)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
