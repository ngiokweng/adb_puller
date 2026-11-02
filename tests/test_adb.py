"""Test remote quoting, metadata framing, and the actual binary subprocess pipe."""

from __future__ import annotations

import io
import hashlib
from pathlib import Path
import random
import re
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

from adb_puller.adb import AdbClient, AdbError, DirectoryEntry, FileInfo, _ArchiveReader


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
                with self.assertRaises(AdbError):
                    AdbClient().path_kind(path)
                with self.assertRaises(AdbError):
                    AdbClient().list_directory(path)

    def test_path_kind(self) -> None:
        """Recognize both source types and reject unexpected control output."""
        client = AdbClient()
        for kind in ("directory", "file"):
            with patch.object(client, "_control", return_value=kind):
                self.assertEqual(client.path_kind("/private/source"), kind)
        with patch.object(client, "_control", return_value="unknown"):
            with self.assertRaises(AdbError):
                client.path_kind("/private/source")

    def test_directory_listing(self) -> None:
        """Preserve unusual filenames and sort children after their parents."""
        client = AdbClient()
        filename = "空 格 ' $; `id`\n.bin"
        payload = (
            f"d\0.\0f\0./sub/{filename}\0d\0./empty\0"
            "d\0./sub\0f\0./.hidden\0ADB_PULLER_OK\0"
        ).encode()
        with patch.object(client, "_run", return_value=payload):
            self.assertEqual(client.list_directory("/private/source"), [
                DirectoryEntry(".hidden", False), DirectoryEntry("empty", True),
                DirectoryEntry("sub", True), DirectoryEntry(f"sub/{filename}", False),
            ])

    def test_invalid_directory_listing(self) -> None:
        """Reject partial listings, escaping paths, links and invalid inventories."""
        payloads = (
            b"", b"d\0.\0", b"ADB_PULLER_OK\0",
            b"banner\nd\0.\0ADB_PULLER_OK\0",
            b"f\0.\0ADB_PULLER_OK\0", b"d\0.\0f\0./bad\xff\0ADB_PULLER_OK\0",
            b"d\0.\0f\0/absolute\0ADB_PULLER_OK\0",
            b"d\0.\0f\0./../escape\0ADB_PULLER_OK\0",
            b"d\0.\0f\0./sub/file\0ADB_PULLER_OK\0",
            b"d\0.\0f\0./same\0f\0./same\0ADB_PULLER_OK\0",
            b"d\0.\0x\0./link\0ADB_PULLER_OK\0",
        )
        client = AdbClient()
        for payload in payloads:
            with self.subTest(payload=payload):
                with patch.object(client, "_run", return_value=payload):
                    with self.assertRaises(AdbError):
                        client.list_directory("/private/source")

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

    def test_archive_footer_boundaries(self) -> None:
        """Recognize a footer split across arbitrary byte boundaries."""
        payload = b"binary\0archive\xffdata"
        frame = payload + b"\n" + hashlib.sha256(payload).hexdigest().encode() + b"\nADB_PULLER_ARCHIVE_OK\n"
        for width in (1, 7, 64, 4096):
            with self.subTest(width=width):
                chunks = iter([frame[i:i + width] for i in range(0, len(frame), width)] + [None])
                reader = _ArchiveReader(lambda: next(chunks), lambda chunk: None)
                self.assertEqual(reader.read(), payload)
                self.assertTrue(reader.ended)

    def _archive_stream(self, mode, callback=None, *, read_all=True):
        client = AdbClient()
        fixture = str(Path(__file__).with_name("stream_fixture.py"))
        processes = []
        original_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        try:
            with patch.object(client, "_root_command", return_value=[sys.executable, fixture, mode]):
                with patch("adb_puller.adb.subprocess.Popen", side_effect=spawn):
                    with client.stream_directory("/private/source", callback or (lambda c: None)) as source:
                        return source.read() if read_all else source.read(1)
        finally:
            self.assertTrue(all(process.poll() is not None and process.stdout.closed for process in processes))

    def test_archive_stream_and_final_verification(self) -> None:
        """Accept framed raw/gzip streams and check hashes even after early reads."""
        self.assertEqual(self._archive_stream("archive_raw"), bytes(range(256)) * 8192)
        self.assertTrue(self._archive_stream("archive_gzip").startswith(b"\x1f\x8b"))
        self.assertEqual(self._archive_stream("archive_raw", read_all=False), b"\0")
        for mode in ("archive_bad_hash", "archive_no_footer", "archive_error"):
            with self.subTest(mode=mode), self.assertRaises(AdbError):
                self._archive_stream(mode, read_all=False)

    def test_archive_cancellation_reaps_process(self) -> None:
        """Reap a blocked pipe reader when its progress callback cancels."""
        def cancel(chunk):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self._archive_stream("hang", cancel)
