#!/usr/bin/env python3
"""Own Ripple's processes and local dependencies for one foreground session."""

import argparse
import fcntl
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent


class SessionError(Exception):
    pass


class Session:
    def __init__(self, root=ROOT, grace=35):
        self.root, self.grace = Path(root), grace
        self.stopping = False
        self.cleaning = False
        self.processes, self.containers = [], []
        self.compose, self.lock = False, None
        self.env = os.environ.copy()
        self.adb = None
        self.build_temp = None
        self.log_relays = []

    def record_diagnostic(self, message, source="launcher", level="error"):
        try:
            text = str(message)
            text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED authorization]", text)
            text = re.sub(r"(?i)(password|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
            text = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@", r"\1REDACTED@", text)
            for key, value in self.env.items():
                if value and len(value) >= 4 and any(word in key.upper() for word in ("API_KEY", "PASSWORD", "TOKEN")):
                    text = text.replace(value, "[REDACTED]")
            pending = self.root / "data" / "logs" / "pending"
            pending.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = pending / f"{time.time_ns()}-{uuid.uuid4().hex}.json"
            temp = target.with_suffix(".tmp")
            record = {"ts": datetime.now(timezone.utc).isoformat(), "level": level, "tag": source, "text": f"[{source}] {text}"}
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(record, stream)
            temp.rename(target)
        except OSError:
            pass  # The original terminal diagnostic remains available.

    def relay_errors(self, name, child):
        native_panic = False
        for line in child.stderr:
            sys.stderr.write(line)
            sys.stderr.flush()
            if name == "backend":
                native_panic = native_panic or line.startswith(("panic:", "fatal error:", "runtime:"))
                if not native_panic:
                    continue  # Standard Go logs already enter the journal.
            level = "error"
            if name == "ADB":
                # adb server stderr is logcat-style: "MM-DD HH:MM:SS.mmm pid tid <P> adb : ..."
                m = re.match(r"\S+ \S+\s+\d+\s+\d+ ([VDIWEF]) ", line)
                if m and m.group(1) in "VDI":
                    continue  # Transport chatter stays on the terminal only.
                level = "warn" if m and m.group(1) == "W" else "error"
            self.record_diagnostic(line.rstrip(), name, level)

    def acquire(self):
        runtime = self.root / "data" / "session"
        runtime.mkdir(parents=True, exist_ok=True)
        self.lock = (runtime / "launcher.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            self.lock = None
            raise SessionError("Ripple is already open in another terminal.") from None

    def command(self, args, timeout=40, env=None):
        child = subprocess.Popen(args, cwd=self.root, env=env or self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while True:
                if self.stopping and not self.cleaning:
                    raise SessionError("Session stopped during startup.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args[0], timeout)
                try:
                    output, error_output = child.communicate(timeout=min(0.1, remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if child.poll() is None:
                self.signal_group(child, signal.SIGTERM)
                try:
                    child.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    self.signal_group(child, signal.SIGKILL)
                    child.communicate()
        if child.returncode:
            self.record_diagnostic(error_output or f"{args[0]} operation failed (exit {child.returncode}).")
            # Neither argv nor stderr is echoed: configuration may hold credentials.
            raise SessionError(f"{args[0]} operation failed (exit {child.returncode}).")
        return output

    def start(self, name, args, cwd=None):
        if self.stopping:
            raise SessionError("Session stopped during startup.")
        child = subprocess.Popen(args, cwd=cwd or self.root, env=self.env,
                                 stderr=subprocess.PIPE, text=True, errors="replace", start_new_session=True)
        relay = threading.Thread(target=self.relay_errors, args=(name, child), daemon=True)
        relay.start()
        self.log_relays.append(relay)
        self.processes.append((name, child))
        return child

    @staticmethod
    def port_open(port):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            return False

    def configured_database(self):
        path = Path(self.env.get("ANDROIDLAB_CONFIG", self.root / "config.json"))
        if not path.is_absolute():
            path = self.root / path
        db = json.loads(path.read_text()).get("database", {}) if path.exists() else {}
        dsn = self.env.get("ANDROIDLAB_PG_DSN") or db.get("dsn")
        if dsn:
            parsed = urlparse(dsn)
            return parsed.hostname, parsed.port or 5432
        return db.get("host", "127.0.0.1"), db.get("port", 5432)

    def start_dependencies(self):
        explicit = self.env.get("ANDROIDLAB_SESSION_CONTAINERS")
        if explicit is not None:
            names = [n.strip() for n in explicit.split(",") if n.strip()]
        else:
            host, port = self.configured_database()
            names = ["android-lab-pg"] if host in ("localhost", "127.0.0.1", "::1") and port == 55434 else []
        for name in dict.fromkeys(names):
            info = json.loads(self.command(["docker", "inspect", name]))[0]
            if name == "android-lab-pg":
                bindings = info["HostConfig"].get("PortBindings", {}).get("5432/tcp", [])
                if not any(b.get("HostPort") == "55434" and b.get("HostIp") == "127.0.0.1" for b in bindings):
                    raise SessionError("android-lab-pg is not the isolated Ripple database.")
            self.containers.append(name)  # Unwind even a partially successful start.
            self.command(["docker", "update", "--restart=no", name])
            self.command(["docker", "start", name])
            deadline = time.monotonic() + 40
            while not self.stopping:
                state = json.loads(self.command(["docker", "inspect", name]))[0]["State"]
                if not state["Running"]:
                    raise SessionError(f"Dependency {name} exited during startup.")
                health = state.get("Health", {}).get("Status")
                if health == "healthy" or health is None:
                    break
                if health == "unhealthy" or time.monotonic() >= deadline:
                    raise SessionError(f"Dependency {name} did not become ready.")
                time.sleep(0.2)
            self.start("dependency " + name, ["docker", "wait", name])
        if "android-lab-pg" in self.containers:
            deadline = time.monotonic() + 30
            while not self.stopping:
                try:
                    self.command(["docker", "exec", "android-lab-pg", "pg_isready", "-h", "127.0.0.1", "-U", "androidlab", "-d", "androidlab"])
                    break
                except SessionError:
                    if time.monotonic() >= deadline:
                        raise SessionError("Ripple PostgreSQL did not become ready.") from None
                    time.sleep(0.2)

    def start_adb(self):
        adb = shutil.which("adb")
        if not adb:
            return None
        # Never kill the shared ADB server used by independently opened tools.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        address = f"tcp:127.0.0.1:{port}"
        self.env["ADB_SERVER_SOCKET"] = address
        self.adb = adb
        # This ADB build accepts a port-only listen socket; no -a means loopback.
        self.start("ADB", [adb, "--one-device", "ripple-session", "-L", f"tcp:{port}", "server", "nodaemon"])
        deadline = time.monotonic() + 10
        while not self.port_open(port):
            if self.stopping or time.monotonic() >= deadline:
                raise SessionError("Ripple's private ADB server did not start.")
            time.sleep(0.1)
        return adb

    def sync_devices(self, adb):
        devices = set(filter(None, self.env.get("ANDROIDLAB_ADB_DEVICES", "").split(",")))
        if self.port_open(5037):
            shared_env = self.env.copy()
            shared_env["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:5037"
            try:
                output = self.command([adb, "devices"], timeout=3, env=shared_env)
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == "device" and ":" in parts[0]:
                        devices.add(parts[0])
            except (SessionError, subprocess.TimeoutExpired):
                pass
        if self.port_open(6555):
            devices.add("127.0.0.1:6555")
        try:
            current = self.command([adb, "devices"], timeout=3)
            for device in devices:
                if device not in current:
                    self.command([adb, "connect", device], timeout=3)
        except (SessionError, subprocess.TimeoutExpired):
            pass

    def run(self, dev=False, compose=False, args=()):
        self.acquire()
        adb = None
        if compose:
            self.compose = True
            self.command(["docker", "compose", "up", "--wait", "--wait-timeout", "90", *args], timeout=150)
            self.start("Compose logs", ["docker", "compose", "logs", "--follow"])
        else:
            for port in ([8797, 8798, 3001] if dev else [8797, 8798]):
                if self.port_open(port):
                    raise SessionError(f"Port {port} is in use; close the existing instance first.")
            binary = self.root / ("androidlab-dev" if dev else "androidlab")
            if dev:
                if "GOTMPDIR" not in self.env:
                    self.build_temp = tempfile.TemporaryDirectory(prefix="build-", dir=self.root / "data" / "session")
                    self.env["GOTMPDIR"] = self.build_temp.name
                build = self.start("build", ["go", "build", "-o", str(binary), "./cmd/artex"])
                while build.poll() is None and not self.stopping:
                    time.sleep(0.1)
                if self.stopping:
                    return 0
                if build.returncode:
                    raise SessionError("Ripple backend build failed.")
                self.processes.remove(("build", build))
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise SessionError("Build Ripple first: ./build-android.sh")
            self.start_dependencies()
            adb = self.start_adb()
            self.start("backend", [str(binary), *args])
            if dev:
                self.start("frontend", ["npm", "run", "dev"], cwd=self.root / "web")
            print(f"Ripple: http://localhost:{3001 if dev else 8797} — Ctrl-C or close this terminal to stop.", flush=True)
        next_sync = 0
        while not self.stopping:
            for name, child in self.processes:
                code = child.poll()
                if code is not None:
                    if name == "backend" and code == 0:
                        return 0
                    raise SessionError(f"{name} exited (code {code}); closing the session.")
            if adb and time.monotonic() >= next_sync:
                self.sync_devices(adb)
                next_sync = time.monotonic() + 5
            elif compose and time.monotonic() >= next_sync:
                states = self.command(["docker", "compose", "ps", "--all", "--format", "{{.State}}"], timeout=5).split()
                if not states or any(state != "running" for state in states):
                    raise SessionError("A Compose service exited; closing the session.")
                next_sync = time.monotonic() + 2
            time.sleep(0.1)
        return 0

    def run_assessment(self, args=()):
        """Own the CLI build, private ADB server and assessment process."""
        self.build_temp = tempfile.TemporaryDirectory(prefix="ripple-assess-")
        binary = Path(self.build_temp.name) / "apkassess"
        self.command(["go", "build", "-o", str(binary), "./cmd/apkassess"], timeout=180)
        if not any(arg in ("-h", "--help") for arg in args):
            adb = self.start_adb()
            if adb:
                self.sync_devices(adb)
        child = self.start("assessment", [str(binary), *args])
        while child.poll() is None and not self.stopping:
            time.sleep(0.1)
        return child.returncode if child.returncode is not None else 0

    @staticmethod
    def signal_group(child, sig):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass

    def stop_process(self, name, child):
        if child.poll() is None:
            try:
                child.terminate()
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=self.grace if name in ("backend", "assessment") else min(self.grace, 5))
            except subprocess.TimeoutExpired:
                pass
        # Also reap descendants whose parent already exited (npm, shells, tools).
        self.signal_group(child, signal.SIGTERM)
        self.signal_group(child, signal.SIGKILL)
        child.wait()

    def close(self):
        self.stopping = True
        self.cleaning = True
        clean = True
        processes, self.processes = self.processes, []
        for name, child in sorted(processes, key=lambda item: item[0] not in ("backend", "assessment")):
            if name == "ADB" and self.adb:
                # Also stop any replacement daemon an ADB client may have
                # spawned after the foreground server failed. Socket is private.
                try:
                    self.command([self.adb, "kill-server"], timeout=5)
                except (SessionError, subprocess.TimeoutExpired):
                    pass
            self.stop_process(name, child)
        for relay in self.log_relays:
            relay.join(timeout=2)
        self.log_relays = []
        for _, child in processes:
            if child.stderr is not None:
                child.stderr.close()
        containers, self.containers = self.containers, []
        for name in reversed(containers):
            try:
                self.command(["docker", "stop", "--time", "30", name], timeout=40)
            except (SessionError, subprocess.TimeoutExpired) as exc:
                clean = False
                self.record_diagnostic(f"Could not stop {name}: {exc}")
                print(f"[Ripple] Could not stop {name}: {exc}", file=sys.stderr)
        if self.compose:
            self.compose = False
            try:
                self.command(["docker", "compose", "stop", "--timeout", "30"], timeout=70)
            except (SessionError, subprocess.TimeoutExpired) as exc:
                clean = False
                self.record_diagnostic(f"Could not stop Compose services: {exc}")
                print(f"[Ripple] Could not stop Compose services: {exc}", file=sys.stderr)
        if self.build_temp:
            self.build_temp.cleanup()
            self.build_temp = None
        if self.lock:
            self.lock.close()
            self.lock = None
        return clean


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev", action="store_true")
    parser.add_argument("--compose", action="store_true")
    assessing = sys.argv[1:2] == ["assess"]
    if assessing:
        options, args = parser.parse_args([]), sys.argv[2:]
    else:
        options, args = parser.parse_known_args()
    if options.dev and options.compose:
        parser.error("choose --dev or --compose")
    session = Session()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: setattr(session, "stopping", True))
    try:
        code = session.run_assessment(args=args) if assessing else session.run(dev=options.dev, compose=options.compose, args=args)
    except (SessionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        session.record_diagnostic(exc)
        print(f"[Ripple] {exc}", file=sys.stderr)
        code = 0 if session.stopping else 1
    finally:
        clean = session.close()
    return code if clean else 1


if __name__ == "__main__":
    sys.exit(main())
