"""Exercise publication, integrity checks, and cleanup without an Android device."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adb_puller.adb import AdbError, FileInfo, Snapshot
from adb_puller.transfer import pull_file


class FixtureClient:
    """Provide controlled file bytes and source snapshots for transfer tests."""

    def __init__(self, data: bytes, *, delivered: bytes | None = None) -> None:
        """Configure source data and optionally different bytes delivered by ADB."""
        self.data = data
        self.delivered = data if delivered is None else delivered
        self.before = Snapshot(FileInfo(len(data), 1, 1, 2, 3), hashlib.sha256(data).hexdigest())
        self.after = self.before
        self.inspections = 0
        self.failure: BaseException | None = None

    def inspect_file(self, remote: str) -> Snapshot:
        """Return the initial snapshot once, then the post-transfer snapshot."""
        self.inspections += 1
        return self.before if self.inspections == 1 else self.after

    def stream_file(self, remote, destination, expected_size, on_chunk) -> int:
        """Deliver fixture bytes, optionally fail, and return delivered byte count."""
        for offset in range(0, len(self.delivered), 4096):
            chunk = self.delivered[offset : offset + 4096]
            destination.write(chunk)
            on_chunk(chunk)
        if self.failure:
            raise self.failure
        return len(self.delivered)


class TransferTests(unittest.TestCase):
    """Verify that only complete, stable, matching files become final outputs."""

    def setUp(self) -> None:
        """Create an isolated local destination directory for each case."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.target = self.root / "output.bin"
        self.data = bytes(range(256)) * 100

    def assert_no_parts(self) -> None:
        """Assert that no failed transfer left a temporary file behind."""
        self.assertEqual(list(self.root.rglob("*.part")), [])

    def test_binary_success(self) -> None:
        """Preserve every binary byte and report the verified digest and count."""
        progress = []
        result = pull_file(FixtureClient(self.data), "/private/source", self.target,
                           progress=lambda copied, total: progress.append((copied, total)))
        self.assertEqual(self.target.read_bytes(), self.data)
        self.assertEqual(result.size, len(self.data))
        self.assertEqual(result.sha256, hashlib.sha256(self.data).hexdigest())
        self.assertEqual(progress[-1], (len(self.data), len(self.data)))
        self.assert_no_parts()

    def test_empty_file(self) -> None:
        """Accept an empty regular file with the correct empty digest."""
        result = pull_file(FixtureClient(b""), "/private/empty", self.target)
        self.assertEqual(self.target.read_bytes(), b"")
        self.assertEqual(result.size, 0)

    def test_existing_directory(self) -> None:
        """Use the Android basename when the local destination is a directory."""
        result = pull_file(FixtureClient(self.data), "/private/file.bin", self.root)
        self.assertEqual(result.destination, self.root / "file.bin")

    def test_create_parent(self) -> None:
        """Create missing parent directories for an explicit destination file."""
        target = self.root / "new" / "nested" / "file.bin"
        pull_file(FixtureClient(self.data), "/private/file", target)
        self.assertEqual(target.read_bytes(), self.data)

    def test_existing_file_preserved(self) -> None:
        """Reject existing destinations before reading the phone source."""
        self.target.write_bytes(b"old")
        client = FixtureClient(self.data)
        with self.assertRaises(FileExistsError):
            pull_file(client, "/private/file", self.target)
        self.assertEqual(client.inspections, 0)
        self.assertEqual(self.target.read_bytes(), b"old")

    def test_overwrite_after_success(self) -> None:
        """Replace an existing destination only after verification succeeds."""
        self.target.write_bytes(b"old")
        pull_file(FixtureClient(self.data), "/private/file", self.target, overwrite=True)
        self.assertEqual(self.target.read_bytes(), self.data)
        self.assert_no_parts()

    def test_truncation(self) -> None:
        """Reject a truncated transfer and remove its temporary file."""
        client = FixtureClient(self.data, delivered=self.data[:-1])
        with self.assertRaises(AdbError):
            pull_file(client, "/private/file", self.target)
        self.assertFalse(self.target.exists())
        self.assert_no_parts()

    def test_same_size_corruption_preserves_old_file(self) -> None:
        """Reject corrupt bytes even when their count matches, preserving old data."""
        self.target.write_bytes(b"old")
        corrupt = b"!" + self.data[1:]
        with self.assertRaisesRegex(AdbError, "SHA-256"):
            pull_file(FixtureClient(self.data, delivered=corrupt), "/private/file",
                      self.target, overwrite=True)
        self.assertEqual(self.target.read_bytes(), b"old")
        self.assert_no_parts()

    def test_source_changed(self) -> None:
        """Reject a source that changed after otherwise correct bytes arrived."""
        client = FixtureClient(self.data)
        client.after = Snapshot(client.before.info, "0" * 64)
        with self.assertRaises(AdbError):
            pull_file(client, "/private/file", self.target)
        self.assertFalse(self.target.exists())
        self.assert_no_parts()

    def test_interruption(self) -> None:
        """Remove temporary output if cancellation interrupts a transfer."""
        client = FixtureClient(self.data)
        client.failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            pull_file(client, "/private/file", self.target)
        self.assertFalse(self.target.exists())
        self.assert_no_parts()

    def test_disconnect(self) -> None:
        """Clean up and preserve an existing target when ADB reports a failure."""
        self.target.write_bytes(b"old")
        client = FixtureClient(self.data)
        client.failure = AdbError("device disconnected")
        with self.assertRaises(AdbError):
            pull_file(client, "/private/file", self.target, overwrite=True)
        self.assertEqual(self.target.read_bytes(), b"old")
        self.assert_no_parts()

    def test_fsync_failure(self) -> None:
        """Do not publish a file when flushing local storage fails."""
        with patch("adb_puller.transfer.os.fsync", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                pull_file(FixtureClient(self.data), "/private/file", self.target)
        self.assertFalse(self.target.exists())
        self.assert_no_parts()

    def test_destination_created_during_transfer(self) -> None:
        """Preserve a destination created by another process during transfer."""
        def stage(message: str) -> None:
            if "SHA-256" in message and list(self.root.glob("*.part")):
                self.target.write_bytes(b"created concurrently")

        with self.assertRaises(FileExistsError):
            pull_file(FixtureClient(self.data), "/private/file", self.target, stage=stage)
        self.assertEqual(self.target.read_bytes(), b"created concurrently")
        self.assert_no_parts()

    def test_insufficient_space(self) -> None:
        """Reject insufficient free space before creating temporary output."""
        with patch("adb_puller.transfer.shutil.disk_usage") as disk_usage:
            disk_usage.return_value.free = 0
            with self.assertRaises(AdbError):
                pull_file(FixtureClient(self.data), "/private/file", self.target)
        self.assertFalse(self.target.exists())
        self.assert_no_parts()
