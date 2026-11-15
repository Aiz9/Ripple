import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

spec = importlib.util.spec_from_file_location("ripple_session", Path(__file__).with_name("session.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


class SessionTests(unittest.TestCase):
    def test_adb_relay_keeps_only_warnings_and_errors_at_their_level(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)
            child = type("Child", (), {"stderr": [
                "11-13 13:47:51.019 1 2 I adb     : adb.cpp:173 127.0.0.1:6555: already offline\n",
                "11-13 13:47:51.019 1 2 W adb     : slow\n",
                "11-13 13:47:51.019 1 2 E adb     : broken\n",
            ]})()
            with unittest.mock.patch.object(sys, "stderr"):
                session.relay_errors("ADB", child)
            pending = Path(directory) / "data" / "logs" / "pending"
            levels = sorted(json.loads(p.read_text())["level"] for p in pending.glob("*.json"))
            self.assertEqual(levels, ["error", "warn"])

    def test_assessment_command_forwards_exit_and_cleans_build_without_server_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)
            binaries = []

            def build(args, **kwargs):
                self.assertEqual(args[:2], ["go", "build"])
                binary = Path(args[args.index("-o") + 1])
                binary.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(7)\n")
                binary.chmod(0o700)
                binaries.append(binary)

            session.command = build
            session.start_adb = lambda: None
            try:
                self.assertEqual(session.run_assessment(["--apk", "fixture.apk", "--device", "fixture"]), 7)
                self.assertIsNone(session.lock)
                self.assertEqual(session.containers, [])
            finally:
                session.close()
            self.assertFalse(binaries[0].exists())

    def test_assessment_help_does_not_start_adb(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)

            def build(args, **kwargs):
                binary = Path(args[args.index("-o") + 1])
                binary.write_text(f"#!{sys.executable}\n")
                binary.chmod(0o700)

            def unexpected_adb():
                self.fail("help started an ADB server")

            session.command = build
            session.start_adb = unexpected_adb
            try:
                self.assertEqual(session.run_assessment(["--help"]), 0)
            finally:
                session.close()

    def test_cancellation_interrupts_startup_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)
            marker = Path(directory) / "startup-child"
            program = f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));time.sleep(60)"
            timer = threading.Timer(0.3, lambda: setattr(session, "stopping", True))
            timer.start()
            started = time.monotonic()
            try:
                with self.assertRaises(module.SessionError):
                    session.command([sys.executable, "-c", program])
                self.assertLess(time.monotonic() - started, 3)
                self.assertFalse(alive(int(marker.read_text())))
            finally:
                timer.cancel()
                session.close()

    def test_closing_reaps_grandchildren_after_parent_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory, grace=0.2)
            marker = Path(directory) / "child"
            program = ("import subprocess,sys; "
                       "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                       f"open({str(marker)!r},'w').write(str(p.pid))")
            session.start("frontend", [sys.executable, "-c", program]).wait(timeout=5)
            child = int(marker.read_text())
            self.assertTrue(alive(child))
            session.close()
            deadline = time.monotonic() + 2
            while alive(child) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(alive(child), "orphaned Node/tool descendants must be stopped")
            session.close()  # Cleanup must be safe after partial failures too.

    def test_lock_blocks_second_session_and_allows_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            first = module.Session(directory)
            second = module.Session(directory)
            first.acquire()
            with self.assertRaises(module.SessionError):
                second.acquire()
            second.close()
            first.close()
            second.acquire()
            second.close()

    def test_failed_dependency_start_still_unwinds_without_deleting_data(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)
            session.env["ANDROIDLAB_SESSION_CONTAINERS"] = "fixture"
            commands = []

            def command(args, **kwargs):
                commands.append(args)
                if args[1] == "inspect":
                    return json.dumps([{"HostConfig": {}, "State": {"Running": False}}])
                if args[1] == "start":
                    raise module.SessionError("fixture startup failed")
                return ""

            session.command = command
            with self.assertRaises(module.SessionError):
                session.start_dependencies()
            session.close()
            self.assertIn(["docker", "stop", "--time", "30", "fixture"], commands)
            self.assertFalse(any("rm" in c or "down" in c for c in commands))

    def test_database_stops_after_backend_flushes(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory, grace=2)
            marker = Path(directory) / "flushed"
            ready = Path(directory) / "ready"
            program = f"""
import signal,time
from pathlib import Path
def stop(*_):
 Path({str(marker)!r}).write_text('evidence saved')
 raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
Path({str(ready)!r}).touch()
while True: time.sleep(0.01)
"""
            session.start("backend", [sys.executable, "-c", program])
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            session.containers = ["fixture-db"]

            def command(args, **kwargs):
                self.assertTrue(marker.exists(), "database stopped before evidence was saved")
                return ""

            session.command = command
            self.assertTrue(session.close())

    def test_remote_database_is_not_managed(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)
            session.env.pop("ANDROIDLAB_SESSION_CONTAINERS", None)
            session.env["ANDROIDLAB_PG_DSN"] = "postgres://fixture@remote.example/db"
            session.command = lambda *args, **kwargs: self.fail("remote database must not be stopped")
            session.start_dependencies()
            self.assertTrue(session.close())

    def test_compose_failure_stops_project_without_removing_volumes(self):
        with tempfile.TemporaryDirectory() as directory:
            session = module.Session(directory)
            commands = []

            def command(args, **kwargs):
                commands.append(args)
                if "up" in args:
                    raise module.SessionError("fixture healthcheck failure")
                return ""

            session.command = command
            with self.assertRaises(module.SessionError):
                session.run(compose=True)
            self.assertTrue(session.close())
            self.assertIn(["docker", "compose", "stop", "--timeout", "30"], commands)
            self.assertFalse(any("down" in c or "rm" in c for c in commands))

    def test_termination_signals_cleanup_and_allow_relaunch(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "ready"
                # Execute the real signal handlers, with only startup replaced by a fixture.
                program = f"""
import importlib.util,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('session',{str(Path(__file__).with_name('session.py').resolve())!r})
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=m.Session
class Fixture(original):
 def __init__(self): super().__init__({directory!r},grace=0.2)
 def run(self,**kwargs):
  self.acquire()
  child=self.start('backend',[sys.executable,'-c','import time;time.sleep(60)'])
  Path({str(marker)!r}).write_text(str(child.pid))
  while not self.stopping: time.sleep(0.01)
  return 0
m.Session=Fixture
sys.exit(m.main())
"""
                proc = subprocess.Popen([sys.executable, "-c", program])
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists())
                    child = int(marker.read_text())
                    proc.send_signal(sig)
                    self.assertEqual(proc.wait(timeout=5), 0)
                    self.assertFalse(alive(child))
                    reopened = module.Session(directory)
                    reopened.acquire()
                    reopened.close()
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()


if __name__ == "__main__":
    unittest.main()
