#!/usr/bin/env python3
"""Build exact upstream source plus the temporary Safari patch; never sign with Apple credentials."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import urllib.parse
import zipfile

PATCH_BASE = "7c9189258b6750fdeab2eb9f45b6a32c63540ce3"
PATCH_HEAD = "ce097529f613ff935afc686b6d6bef60e71504ff"
UPSTREAM = "https://github.com/and101/RedditFilter.git"
FORK = "https://github.com/dukevin/RedditFilter.git"
OWN_EXTENSION = "RedditFilterSafari.appex"
MAX_IPA_BYTES = 500 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(*args, cwd=None, capture=False, timeout=None):
    return subprocess.run(args, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None, timeout=timeout).stdout


def checked_input(name, pattern):
    value = os.environ[name]
    require(re.fullmatch(pattern, value), "Invalid " + name)
    return value


def archive_info(archive):
    names = archive.namelist()
    require(sum(item.file_size for item in archive.infolist()) <= MAX_EXPANDED_BYTES, "Expanded IPA exceeds 2 GiB")
    require(len(names) == len(set(names)), "IPA contains duplicate ZIP entries")
    require(len(names) == len({name.casefold() for name in names}), "IPA contains case-colliding ZIP entries")
    require(all(stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR)
                for item in archive.infolist()), "IPA contains symlinks or special files")
    require(all(not name.startswith("/") and "//" not in name and ".." not in PurePosixPath(name).parts and "\\" not in name
                for name in names), "Unsafe IPA path")
    plists = [name for name in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
    require(len(plists) == 1, "Expected exactly one application")
    app = plists[0][:-len("Info.plist")]
    info = plistlib.loads(archive.read(plists[0]))
    executable = info["CFBundleExecutable"]
    require(isinstance(executable, str) and PurePosixPath(executable).name == executable,
            "Invalid app executable")
    require(app + executable in names, "Missing app executable")
    plugins = {name for name in names if re.fullmatch(re.escape(app) + r"PlugIns/[^/]+\.appex/Info\.plist", name)}
    return app, info, plugins


def verify_existing_loads(ipa, work):
    from nuc_tool import counts
    with zipfile.ZipFile(ipa) as archive:
        app, info, _ = archive_info(archive)
        binary = work / "base-binary"
        binary.write_bytes(archive.read(app + info["CFBundleExecutable"]))
    for value, rpath in [("@rpath/RedditFilter.dylib", False), ("@rpath/RedditSideloadFix.dylib", False),
                          ("@executable_path/Frameworks", True)]:
        found = counts(str(binary), value, rpath)
        require(found and all(count == 1 for count in found), "Official base loader layout changed: " + value)


def normalize_base(source, destination):
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(destination, "w") as output:
        app, info, plugins = archive_info(archive)
        info.pop("ALTBundleIdentifier", None)
        types = []
        for item in info.get("CFBundleURLTypes", []):
            item = dict(item)
            item["CFBundleURLSchemes"] = [scheme for scheme in item.get("CFBundleURLSchemes", [])
                                           if scheme != "redditfilter"]
            if item["CFBundleURLSchemes"]:
                types.append(item)
        info["CFBundleURLTypes"] = types
        owned_prefix = app + "PlugIns/" + OWN_EXTENSION + "/"
        owned_libraries = {app + "Frameworks/" + name + ".dylib" for name in ["RedditFilter", "RedditSideloadFix"]}
        for entry in archive.infolist():
            if entry.filename.startswith(owned_prefix) or entry.filename in owned_libraries:
                continue
            if entry.filename == app + "Info.plist":
                output.writestr(entry, plistlib.dumps(info, fmt=plistlib.FMT_XML))
            else:
                with archive.open(entry) as src, output.open(entry, "w") as dst:
                    shutil.copyfileobj(src, dst)
    return app, info, plugins


def prepare_source(work, upstream_sha, apply_patch):
    source = work / "source"
    source.mkdir()
    run("git", "init", "-q", str(source))
    run("git", "remote", "add", "origin", UPSTREAM, cwd=source)
    run("git", "fetch", "--no-tags", "origin", "main", cwd=source)
    run("git", "merge-base", "--is-ancestor", upstream_sha, "FETCH_HEAD", cwd=source)
    run("git", "checkout", "--detach", upstream_sha, cwd=source)
    if apply_patch:
        run("git", "fetch", "--no-tags", FORK, PATCH_HEAD, cwd=source)
        run("git", "merge-base", "--is-ancestor", PATCH_BASE, upstream_sha, cwd=source)
        run("git", "-c", "user.name=NUC builder", "-c", "user.email=nuc-builder@localhost",
            "merge", "--no-commit", "--no-ff", PATCH_HEAD, cwd=source)
    tree = run("git", "write-tree", cwd=source, capture=True).strip()
    return source, tree


def adapt_packager(source, work):
    script = source / "build-ipa.sh"
    content = script.read_text()
    old = 'APP_VERSION="$APP_VERSION" INSERT_DYLIB="$INSERT_DYLIB"'
    require(content.count(old) == 1, "Upstream packaging command changed; adapter needs review")
    content = content.replace(old, 'APP_VERSION="$APP_VERSION" INSERT_DYLIB="$RF_INSERT_DYLIB" INSTALL_NAME_TOOL="$RF_INSTALL_NAME_TOOL"')
    script.write_text(content)
    tool = Path(__file__).resolve().with_name("nuc_tool.py")
    for mode, variable in [("insert", "RF_INSERT_DYLIB"), ("install-name", "RF_INSTALL_NAME_TOOL")]:
        wrapper = work / ("native-" + mode)
        wrapper.write_text("#!/bin/sh\nexec python3 " + shlex.quote(str(tool)) + " " + mode + ' "$@"\n')
        wrapper.chmod(0o755)
        os.environ[variable] = str(wrapper)
    os.environ["RF_REAL_INSERT_DYLIB"] = str(source / ".build/insert_dylib")


def verify_output(original, output, work):
    from nuc_tool import counts
    require(output.stat().st_size <= MAX_IPA_BYTES, "Built IPA exceeds 500 MiB")
    with zipfile.ZipFile(original) as base, zipfile.ZipFile(output) as result:
        app, original_info, plugins = archive_info(base)
        out_app, info, out_plugins = archive_info(result)
        require(app == out_app, "Application path changed")
        for key in ["CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"]:
            require(info[key] == original_info[key], "Unexpected app identity/version change: " + key)
        require(plugins <= out_plugins, "An original app extension was lost")
        require(app + "PlugIns/" + OWN_EXTENSION + "/Info.plist" in out_plugins, "Safari extension missing")
        for name in base.namelist():
            if name.startswith(app + "PlugIns/") and not name.startswith(app + "PlugIns/" + OWN_EXTENSION + "/") and not name.endswith("/"):
                require(name in result.namelist() and base.read(name) == result.read(name), "Original extension changed: " + name)
        safari = plistlib.loads(result.read(app + "PlugIns/" + OWN_EXTENSION + "/Info.plist"))
        for key in ["CFBundleShortVersionString", "CFBundleVersion"]:
            require(safari[key] == info[key], "Safari extension version mismatch")
        schemes = [scheme for item in info.get("CFBundleURLTypes", []) for scheme in item.get("CFBundleURLSchemes", [])]
        require(schemes.count("redditfilter") == 1, "Expected one redditfilter URL registration")
        for library in ["RedditFilter", "RedditSideloadFix"]:
            require(app + "Frameworks/" + library + ".dylib" in result.namelist(), library + " missing")
        binary = work / "output-binary"
        binary.write_bytes(result.read(app + info["CFBundleExecutable"]))
        commands = run("xcrun", "otool", "-l", str(binary), capture=True)
        require(not re.search(r"(?m)^\s*cryptid [1-9]", commands), "Built executable is encrypted")
        for value, rpath in [("@rpath/RedditFilter.dylib", False), ("@rpath/RedditSideloadFix.dylib", False),
                              ("@executable_path/Frameworks", True)]:
            found = counts(str(binary), value, rpath)
            require(found and all(count == 1 for count in found), "Missing/duplicate load command: " + value)
        return info, sorted(path.split("/")[-2] for path in out_plugins)


def main():
    upstream_sha = checked_input("UPSTREAM_SHA", r"[0-9a-f]{40}")
    tag = checked_input("BASE_TAG", r"[A-Za-z0-9_.-]{1,100}")
    asset_id = int(checked_input("BASE_ASSET_ID", r"[1-9][0-9]*"))
    base_hash = checked_input("BASE_SHA256", r"[0-9a-f]{64}")
    build_key = checked_input("BUILD_KEY", r"[0-9a-f]{64}")
    apply_patch = checked_input("APPLY_PATCH", r"true|false") == "true"
    require(os.environ["GITHUB_REPOSITORY"] == "dukevin/RedditFilter", "Unexpected worker repository")
    checked_input("GITHUB_SHA", r"[0-9a-f]{40}")
    work = Path(os.environ["RUNNER_TEMP"]) / "nuc-build"
    work.mkdir()
    output_dir = Path(os.environ["RUNNER_TEMP"]) / "nuc-output"
    output_dir.mkdir()
    print("Resolving the exact stable release and upstream source", flush=True)
    release = json.loads(run("gh", "api", "repos/and101/RedditFilter/releases/tags/" + urllib.parse.quote(tag, safe=""), capture=True))
    require(not release["draft"] and not release["prerelease"] and release["tag_name"] == tag, "Not the selected stable release")
    assets = [asset for asset in release["assets"] if asset["id"] == asset_id and asset["name"].endswith(".ipa")]
    require(len(assets) == 1 and assets[0].get("digest") == "sha256:" + base_hash, "Release asset identity/digest changed")
    asset = assets[0]
    require(0 < asset["size"] <= MAX_IPA_BYTES, "Base IPA exceeds 500 MiB")
    require(asset["browser_download_url"].startswith("https://github.com/and101/RedditFilter/releases/download/"), "Unexpected asset host")
    original = work / "official.ipa"
    run("curl", "--fail", "--location", "--retry", "3", "--output", str(original), asset["browser_download_url"])
    require(original.stat().st_size == asset["size"] and sha256(original) == base_hash, "Base IPA checksum/size mismatch")
    source, tree = prepare_source(work, upstream_sha, apply_patch)
    verify_existing_loads(original, work)
    normalized = work / "normalized.ipa"
    normalize_base(original, normalized)
    adapt_packager(source, work)
    os.environ["THEOS"] = str(work / "theos")
    os.environ["SAFARI_EXTENSION"] = "1"
    print("Building all current upstream components and packaging the unsigned IPA", flush=True)
    run("bash", "build-ipa.sh", str(normalized), cwd=source)
    outputs = list((source / "packages").glob("*.ipa"))
    require(len(outputs) == 1, "Expected one newly built IPA")
    info, plugins = verify_output(original, outputs[0], work)
    print("Booting a simulator and running the existing compatibility and regression checks", flush=True)
    devices = json.loads(run("xcrun", "simctl", "list", "devices", "available", "--json", capture=True))
    phone = next(device["udid"] for group in devices["devices"].values() for device in group if device["name"].startswith("iPhone"))
    run("xcrun", "simctl", "bootstatus", phone, "-b", timeout=300)
    for script in run("git", "ls-files", "*.sh", cwd=source, capture=True).splitlines():
        run("bash", "-n", script, cwd=source)
    tests = subprocess.run(["bash", "tests/check-ipa.sh", str(normalized)], cwd=source, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900,
                           env={**os.environ, "LC_ALL": "C"})  # Match the committed baseline's bytewise sort order.
    print(tests.stdout, flush=True)
    require(tests.returncode == 0 and not re.search(r"(?m)^REVIEW |^No booted simulator:", tests.stdout),
            "Compatibility drift or test failure; retaining the previously installed build")
    filter_version = re.search(r"(?m)^PACKAGE_VERSION = (\S+)$", (source / "Makefile").read_text())
    require(filter_version is not None, "Cannot identify current filter version")
    ipa = output_dir / "RedditFilter.ipa"
    shutil.copyfile(outputs[0], ipa)
    manifest = {
        "schema_version": 1, "build_key": build_key, "upstream_sha": upstream_sha,
        "patch_applied": apply_patch, "patch_base_sha": PATCH_BASE, "patch_head_sha": PATCH_HEAD,
        "source_tree_sha": tree, "base": {"tag": tag, "asset_id": asset_id, "sha256": base_hash},
        "reddit_version": info["CFBundleShortVersionString"], "reddit_build": info["CFBundleVersion"],
        "filter_version": filter_version[1], "extensions": plugins, "tests_passed": True,
        "packaging_adapter": "idempotent-jailed-v1", "apple_credentials_used": False,
        "ipa": {"filename": ipa.name, "sha256": sha256(ipa), "size": ipa.stat().st_size},
        "workflow": {"repository": os.environ["GITHUB_REPOSITORY"], "sha": os.environ["GITHUB_SHA"],
                     "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"])}}
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Unsigned IPA and provenance manifest ready", flush=True)


if __name__ == "__main__":
    main()
