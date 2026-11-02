"""Test remote quoting, metadata framing, and the actual binary subprocess pipe."""

from __future__ import annotations

import io
from pathlib import Path
import random
import re
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
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        with patch.object(client, "_stat", side_effect=[FileInfo(1, 1, 1, 1, 1),
                                                       FileInfo(2, 2, 2, 1, 1)]):
            with patch.object(client, "_root_command", return_value=[sys.executable, fixture, "hash"]):
                with self.assertRaises(AdbError):
                    client.inspect_file("/private/file")

    def test_deferred_hash_result(self) -> None:
        """Resolve a framed hash with stable metadata and reuse its snapshot."""
        client = AdbClient()
        info = FileInfo(1, 1, 1, 1, 1)
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        with patch.object(client, "_stat", return_value=info) as stat:
            with patch.object(client, "_root_command", return_value=[sys.executable, fixture, "hash"]):
                with client.inspect_file_later("/private/file") as inspection:
                    self.assertEqual(inspection.info, info)
                    result = inspection.result()
                    self.assertEqual(result.sha256, "a" * 64)
                    self.assertTrue(inspection.done())
                    self.assertIs(inspection.result(), result)
            self.assertEqual(stat.call_count, 2)

    def test_deferred_hash_errors(self) -> None:
        """Reject malformed digests, missing framing, and failed hash commands."""
        client = AdbClient()
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        for mode in ("hash_bad", "hash_unframed", "error"):
            with self.subTest(mode=mode), self.assertRaises(AdbError):
                with patch.object(client, "_stat", return_value=FileInfo(1, 1, 1, 1, 1)):
                    with patch.object(client, "_root_command", return_value=[sys.executable, fixture, mode]):
                        client.inspect_file("/private/file")

    def test_deferred_hash_cancellation(self) -> None:
        """Enter before the hasher exits and reap it immediately on cancellation."""
        client = AdbClient()
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        processes = []
        original_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(client, "_stat", return_value=FileInfo(1, 1, 1, 1, 1)):
            with patch.object(client, "_root_command", return_value=[sys.executable, fixture, "hang"]):
                with patch("adb_puller.adb.subprocess.Popen", side_effect=spawn):
                    with self.assertRaises(KeyboardInterrupt):
                        with client.inspect_file_later("/private/file") as inspection:
                            self.assertEqual(inspection.info.size, 1)
                            self.assertFalse(inspection.done())
                            self.assertIsNone(processes[0].poll())
                            raise KeyboardInterrupt()
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stdout.closed)

    def _stream(self, mode: str, expected: int) -> bytes:
        client = AdbClient(jobs=1, compression="none")
        output = io.BytesIO()
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        with patch.object(client, "_root_command", return_value=[sys.executable, fixture, mode]):
            with patch.object(client, "_transfer_options", return_value=(1, mode.startswith("gzip"))):
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

    def test_gzip_binary_and_empty(self) -> None:
        """Decode binary gzip bytes and accept a valid compressed empty file."""
        self.assertEqual(self._stream("gzip", 256 * 8192), bytes(range(256)) * 8192)
        self.assertEqual(self._stream("gzip_empty", 0), b"")

    def test_invalid_gzip(self) -> None:
        """Reject incomplete trailers, CRC errors, trailing bytes, and oversized output."""
        for mode in ("gzip_short", "gzip_corrupt", "gzip_trailing"):
            with self.subTest(mode=mode), self.assertRaises(AdbError):
                self._stream(mode, 256 * 8192)
        with self.assertRaises(AdbError):
            self._stream("gzip", 1)

    def test_auto_compression(self) -> None:
        """Compress repetitive samples and keep incompressible data uncompressed."""
        client = AdbClient()
        with patch.object(client, "_control", return_value="dd gzip"):
            with patch.object(client, "_run", return_value=b"log line\n" * 30000):
                self.assertEqual(client._transfer_options("/private/file", 32 * 1024**2), (4, True))
            with patch.object(client, "_run", return_value=random.Random(0).randbytes(262144)):
                self.assertEqual(client._transfer_options("/private/file", 32 * 1024**2), (4, False))

    def test_missing_optional_tools(self) -> None:
        """Fall back to cat without optional tools and fail an explicit gzip request."""
        client = AdbClient()
        with patch.object(client, "_control", return_value=" "):
            self.assertEqual(client._transfer_options("/private/file", 32 * 1024**2), (1, False))
            client.compression = "gzip"
            with self.assertRaisesRegex(AdbError, "gzip"):
                client._transfer_options("/private/file", 32 * 1024**2)

    def test_large_ranges(self) -> None:
        """Cover a size beyond 4 GiB with aligned, non-overlapping ranges."""
        size = 4 * 1024**3 + 1
        ranges = AdbClient._ranges(size, 4)
        end = 0
        for start, length in ranges:
            self.assertEqual(start, end)
            self.assertEqual(start % 1024**2, 0)
            end = start + length
        self.assertEqual(end, size)

    def _parallel(self, compressed: bool, *, mode: str = "range", callback=None) -> tuple[bytes, list]:
        client = AdbClient()
        size = 32 * 1024**2 + 137
        output = io.BytesIO()
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        processes = []
        original_popen = subprocess.Popen

        def command(script):
            if mode == "spawn_error" and "skip=0 " not in script:
                raise OSError("fixture startup failure")
            start = int(re.search(r"skip=(\d+)", script)[1]) * 1024**2
            length = min(int(re.search(r"count=(\d+)", script)[1]) * 1024**2, size - start)
            selected = "gzip_range" if compressed else "range"
            if mode != "range":
                selected = "error" if mode == "error" and start == 0 else "hang"
            return [sys.executable, fixture, selected, str(start), str(length)]

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        try:
            with patch.object(client, "_transfer_options", return_value=(4, compressed)):
                with patch.object(client, "_root_command", side_effect=command):
                    with patch("adb_puller.adb.subprocess.Popen", side_effect=spawn):
                        received = client.stream_file("/private/file", output, size, callback or (lambda c: None))
            self.assertEqual(received, size)
            return output.getvalue(), processes
        finally:
            self.assertTrue(processes)
            self.assertTrue(all(process.poll() is not None for process in processes))
            self.assertTrue(all(process.stdout.closed for process in processes))

    def test_parallel_out_of_order(self) -> None:
        """Assemble ranges at their offsets even when the first range arrives last."""
        expected = b"".join(bytes([i]) * 1024**2 for i in range(32)) + bytes([32]) * 137
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                data, _ = self._parallel(compressed)
                self.assertEqual(data, expected)

    def test_parallel_cleanup(self) -> None:
        """Reap every child on a worker failure, callback cancellation, or startup failure."""
        with self.assertRaisesRegex(AdbError, "fixture error"):
            self._parallel(False, mode="error")

        def cancel(chunk):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self._parallel(False, mode="hang", callback=cancel)
        with self.assertRaisesRegex(OSError, "startup failure"):
            self._parallel(False, mode="spawn_error")

    def test_adb_timeout(self) -> None:
        """Translate control-command timeouts to a user-facing ADB error."""
        with patch("adb_puller.adb.subprocess.run", side_effect=subprocess.TimeoutExpired("adb", 30)):
            with self.assertRaises(AdbError):
                AdbClient().devices()
