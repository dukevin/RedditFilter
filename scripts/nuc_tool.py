#!/usr/bin/env python3
"""Keep the pinned jailed packager's native injection tools safe on a patched base."""
import os
import re
import subprocess
import sys


def load_commands(text, command, field):
    values = []
    for block in re.split(r"(?m)^Load command \d+\s*$", text):
        if re.search(r"(?m)^\s*cmd " + re.escape(command) + r"\s*$", block):
            match = re.search(r"(?m)^\s*" + field + r" (.+) \(offset \d+\)\s*$", block)
            if not match:
                raise ValueError("Unrecognized otool load command")
            values.append(match[1])
    return values


def counts(binary, value, rpath=False):
    architectures = subprocess.check_output(["xcrun", "lipo", "-archs", binary], text=True).split()
    if not architectures:
        raise ValueError("No Mach-O architecture")
    result = []
    for architecture in architectures:
        text = subprocess.check_output(["xcrun", "otool", "-arch", architecture, "-l", binary], text=True)
        values = load_commands(text, "LC_RPATH", "path") if rpath else (
            load_commands(text, "LC_LOAD_DYLIB", "name") + load_commands(text, "LC_LOAD_WEAK_DYLIB", "name"))
        result.append(values.count(value))
    return result


def needs_insert(existing):
    if existing and all(count == 1 for count in existing):
        return False
    if existing and all(count == 0 for count in existing):
        return True
    raise ValueError("Duplicate or inconsistent Mach-O load commands; refusing to reinject")


def main():
    mode, *args = sys.argv[1:]
    if mode == "insert":
        if len(args) != 5 or args[:3] != ["--inplace", "--weak", "--no-strip-codesig"]:
            raise ValueError("Unexpected insert_dylib invocation")
        value, binary = args[-2:]
        if not value.startswith("@rpath/"):
            raise ValueError("Unexpected injected library path")
        real = os.environ["RF_REAL_INSERT_DYLIB"]
        rpath = False
    elif mode == "install-name":
        real = subprocess.check_output(["xcrun", "--find", "install_name_tool"], text=True).strip()
        if len(args) == 4 and args[0] == "-change":
            subprocess.run([real, *args], check=True, stdin=subprocess.DEVNULL)
            return
        if len(args) != 3 or args[0] != "-add_rpath":
            raise ValueError("Unexpected install_name_tool invocation")
        value, binary = args[1:]
        rpath = True
    else:
        raise ValueError("Unknown native-tool adapter")
    if needs_insert(counts(binary, value, rpath)):
        subprocess.run([real, *args], check=True, stdin=subprocess.DEVNULL)
    final = counts(binary, value, rpath)
    if not final or any(count != 1 for count in final):
        raise ValueError("Native tool did not leave exactly one load command per architecture")


if __name__ == "__main__":
    main()
