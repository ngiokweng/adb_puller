"""Run opt-in smoke tests using disposable, root-only files on a real device."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import tempfile
import unittest
import uuid

from adb_puller import AdbClient, pull_file


@unittest.skipUnless(os.environ.get("ADB_PULLER_DEVICE_TESTS") == "1", "real-device tests are opt-in")
class DeviceTests(unittest.TestCase):
    """Verify real root transfers without reading or changing application data."""

    def setUp(self) -> None:
        """Create a unique root-owned remote directory and a local workspace."""
        self.client = AdbClient(os.environ.get("ADB", "adb"), os.environ.get("ANDROID_SERIAL"))
        self.remote_dir = f"/data/local/tmp/adb-puller-smoke-{uuid.uuid4().hex}"
        self.upload = f"{self.remote_dir}.upload"
        self.remote = self.remote_dir + "/binary 空格 ' $; `id`.bin"
        self.directory = tempfile.TemporaryDirectory(prefix="adb-puller-smoke-")
        self.addCleanup(self.directory.cleanup)
        self.local = Path(self.directory.name)
        self.addCleanup(self._cleanup_remote)
        self._root(f"umask 077; mkdir -- {shlex.quote(self.remote_dir)}")

    def _root(self, script: str) -> None:
        result = self.client._run(
            self.client._root_command(f"set -e; {script}; printf 'ADB_PULLER_TEST_OK\\n'"),
            timeout=30,
        )
        self.assertEqual(result.strip(), b"ADB_PULLER_TEST_OK")

    def _cleanup_remote(self) -> None:
        self._root(
            f"rm -f -- {shlex.quote(self.remote)} {shlex.quote(self.upload)}; "
            f"if test -d {shlex.quote(self.remote_dir)}; then rmdir -- {shlex.quote(self.remote_dir)}; fi"
        )

    def test_root_only_binary(self) -> None:
        """Pull random binary bytes from a root-only directory with a quoted name."""
        data = os.urandom(1024 * 1024 + 137)
        original = self.local / "original.bin"
        original.write_bytes(data)
        self.client._run(self.client._command("push", str(original), self.upload), timeout=60)
        self._root(
            f"mv -- {shlex.quote(self.upload)} {shlex.quote(self.remote)}; "
            f"chown 0:0 -- {shlex.quote(self.remote)}; chmod 600 -- {shlex.quote(self.remote)}"
        )
        output = self.local / "received.bin"
        result = pull_file(self.client, self.remote, output)
        self.assertEqual(output.read_bytes(), data)
        self.assertEqual(result.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.size, len(data))

    @unittest.skipUnless(os.environ.get("ADB_PULLER_LARGE_TEST") == "1", "4 GiB test is opt-in")
    def test_over_four_gib(self) -> None:
        """Transfer 4 GiB plus one byte and check the boundary byte and digest."""
        size = 4 * 1024**3 + 1
        quoted = shlex.quote(self.remote)
        self._root(
            f"truncate -s {size} -- {quoted}; "
            f"printf '\\001' | dd of={quoted} bs=1 seek={size - 1} conv=notrunc 2>/dev/null"
        )
        last_reported = -1

        def progress(copied: int, total: int) -> None:
            nonlocal last_reported
            completed = copied // (512 * 1024**2)
            if completed > last_reported:
                last_reported = completed
                print(f"\nDevice test: {copied / 1024**3:.1f}/{total / 1024**3:.1f} GiB", flush=True)

        output = self.local / "large.bin"
        result = pull_file(
            self.client, self.remote, output, progress=progress,
            stage=lambda message: print(f"\n{message}", flush=True),
        )
        self.assertEqual(result.size, size)
        self.assertEqual(output.stat().st_size, size)
        # Derive an independent known digest in bounded memory. The last byte
        # ensures the test cannot pass after silently dropping data at 4 GiB.
        expected = hashlib.sha256()
        zeros = bytes(4 * 1024**2)
        for _ in range(1024):
            expected.update(zeros)
        expected.update(b"\x01")
        self.assertEqual(result.sha256, expected.hexdigest())
        with output.open("rb") as stream:
            stream.seek(4 * 1024**3)
            self.assertEqual(stream.read(), b"\x01")


if __name__ == "__main__":
    unittest.main()
