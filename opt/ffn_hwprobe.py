#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only host probe boundary. One instance per inventory, injectable in tests."""
import glob
import os
import platform
import shutil
import subprocess


class Probe:
    def __init__(self):
        self.diagnostics = []
        self.section = "system"

    def note(self, source, message, status="partial"):
        item = {"section": self.section, "source": source,
                "status": status, "message": message}
        if item not in self.diagnostics:
            self.diagnostics.append(item)

    def read(self, path, default="", required=False):
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                return stream.read().strip().strip("\0")
        except (OSError, ValueError) as exc:
            if required or isinstance(exc, PermissionError):
                self.note(path, type(exc).__name__)
            return default

    def number(self, path, default=0, required=False):
        value = self.read(path, required=required)
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            self.note(path, "Invalid integer")
            return default

    def entries(self, path):
        try:
            return sorted(os.path.join(path, name) for name in os.listdir(path))
        except OSError as exc:
            self.note(path, type(exc).__name__, "unavailable")
            return []

    def glob(self, pattern):
        return sorted(glob.glob(pattern))

    def link(self, path):
        try:
            return os.readlink(path)
        except OSError:
            return ""

    def exists(self, path):
        return os.path.exists(path)

    def have(self, tool):
        return shutil.which(tool) is not None

    def run(self, command, timeout=6):
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    errors="replace", timeout=timeout,
                                    env={**os.environ, "LC_ALL": "C"})
            if result.returncode == 0:
                return result.stdout
            self.note(command[0], "Command exited %d" % result.returncode)
        except (OSError, subprocess.SubprocessError) as exc:
            self.note(command[0], type(exc).__name__)
        return ""

    def host(self):
        host = platform.uname()
        return {"hostname": host.node, "kernel": host.release,
                "arch": host.machine, "os": host.system}

    def cpu_count(self):
        return os.cpu_count() or 0

    def affinity(self):
        try:
            return sorted(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            return []
