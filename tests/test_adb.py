"""Test remote quoting, metadata framing, and the actual binary subprocess pipe."""

from __future__ import annotations

import io
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

from adb_puller.adb import AdbClient, AdbError, FileInfo


class TransportTests(unittest.TestCase):
    """Cover failure modes at the root-command and subprocess boundaries."""

    def test_remote_quoting(self) -> None:
        """Keep special filename characters inside the cat path argument."""
        path = "/data/private/空 格'; $(touch nope) `id`.bin"
        client = AdbClient("custom-adb", "serial")
        command = client._root_command(f"exec cat -- {shlex.quote(path)}")
        self.assertEqual(command[:4], ["custom-adb", "-s", "serial", "exec-out"])
        outer = shlex.split(command[4])
        self.assertEqual(outer[:2], ["su", "-c"])
        self.assertEqual(shlex.split(outer[2]), ["exec", "cat", "--", path])

    def test_large_size_metadata(self) -> None:
        """Parse a 20 GiB file size without truncating to 32 bits."""
        client = AdbClient()
        with patch.object(client, "_control", return_value="21474836480 1 2 3 4"):
            self.assertEqual(client._stat("/private/file").size, 20 * 1024**3)

    def test_bad_control_frame(self) -> None:
        """Reject missing success markers and unexpected stdout banners."""
        client = AdbClient()
        for payload in (b"123\n", b"banner\n123\nADB_PULLER_OK\n", b""):
            with self.subTest(payload=payload):
                with patch.object(client, "_run", return_value=payload):
                    with self.assertRaises(AdbError):
                        client._control("script")

    def test_invalid_path(self) -> None:
        """Reject relative paths and NUL bytes before invoking ADB."""
        for path in ("relative", "/private/\0file"):
            with self.subTest(path=path):
                with self.assertRaises(AdbError):
                    AdbClient().inspect_file(path)

    def test_source_changes_during_hash(self) -> None:
        """Reject metadata changes while computing the remote digest."""
        client = AdbClient()
        with patch.object(client, "_stat", side_effect=[FileInfo(1, 1, 1, 1, 1),
                                                       FileInfo(2, 2, 2, 1, 1)]):
            with patch.object(client, "_control", return_value="a" * 64):
                with self.assertRaises(AdbError):
                    client.inspect_file("/private/file")

    def _stream(self, mode: str, expected: int) -> bytes:
        client = AdbClient()
        output = io.BytesIO()
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        with patch.object(client, "_root_command", return_value=[sys.executable, fixture, mode]):
            client.stream_file("/private/file", output, expected, lambda chunk: None)
        return output.getvalue()

    def test_binary_pipe_and_large_stderr(self) -> None:
        """Preserve binary stdout while draining more than a pipeful of stderr."""
        data = self._stream("binary", 256 * 8192)
        self.assertEqual(data, bytes(range(256)) * 8192)

    def test_short_pipe(self) -> None:
        """Detect a short stream even when the subprocess exits successfully."""
        with self.assertRaises(AdbError):
            self._stream("binary", 256 * 8192 + 1)

    def test_long_pipe(self) -> None:
        """Stop an oversized stream instead of accepting extra data."""
        with self.assertRaises(AdbError):
            self._stream("binary", 1)

    def test_subprocess_failure(self) -> None:
        """Surface subprocess failure instead of publishing its partial bytes."""
        with self.assertRaisesRegex(AdbError, "fixture error"):
            self._stream("error", 0)

    def test_adb_timeout(self) -> None:
        """Translate control-command timeouts to a user-facing ADB error."""
        with patch("adb_puller.adb.subprocess.run", side_effect=subprocess.TimeoutExpired("adb", 30)):
            with self.assertRaises(AdbError):
                AdbClient().devices()
