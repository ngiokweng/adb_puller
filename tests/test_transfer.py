"""Exercise publication, integrity checks, and cleanup without an Android device."""

from __future__ import annotations

from contextlib import contextmanager
import gzip
import hashlib
import io
import os
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from adb_puller.adb import AdbError, DirectoryEntry, FileInfo, Snapshot
from adb_puller.transfer import DirectoryPullResult, pull, pull_directory, pull_file


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
        self.hash_failure: BaseException | None = None
        self.hash_ready = False
        self.hash_resolved = False
        self.hash_closed = False

    @contextmanager
    def inspect_file_later(self, remote: str):
        """Provide immediate metadata and a deferred, optionally failing snapshot."""
        def resolve():
            self.hash_resolved = True
            if self.hash_failure:
                raise self.hash_failure
            return self.inspect_file(remote)

        try:
            yield SimpleNamespace(info=self.before.info, result=resolve, done=lambda: self.hash_ready)
        finally:
            self.hash_closed = True

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

    def test_transfer_starts_before_hash_resolves(self) -> None:
        """Start copying with metadata while the initial remote digest is pending."""
        client = FixtureClient(self.data)
        stream = client.stream_file

        def copy(*args):
            self.assertFalse(client.hash_resolved)
            return stream(*args)

        with patch.object(client, "stream_file", side_effect=copy):
            pull_file(client, "/private/source", self.target)
        self.assertTrue(client.hash_resolved)
        self.assertTrue(client.hash_closed)
        self.assertEqual(client.inspections, 2)

    def test_deferred_hash_failure_preserves_destination(self) -> None:
        """Refuse publication and close the pending hash if its verification fails."""
        self.target.write_bytes(b"old")
        for ready in (False, True):
            with self.subTest(ready=ready):
                client = FixtureClient(self.data)
                client.hash_failure = AdbError("source changed while hashing")
                client.hash_ready = ready
                progress = []
                with self.assertRaisesRegex(AdbError, "source changed"):
                    pull_file(client, "/private/source", self.target, overwrite=True,
                              progress=lambda copied, total: progress.append(copied))
                self.assertEqual(bool(progress), not ready)
                self.assertEqual(self.target.read_bytes(), b"old")
                self.assertTrue(client.hash_closed)
                self.assert_no_parts()

    def test_out_of_order_hash(self) -> None:
        """Hash the assembled file rather than the arrival order of parallel chunks."""
        data = b"".join(bytes([i]) * 4096 for i in range(7)) + b"tail"
        client = FixtureClient(data)

        def stream(remote, destination, expected_size, on_chunk):
            for start in reversed(range(0, len(data), 4096)):
                chunk = data[start:start + 4096]
                destination.seek(start)
                destination.write(chunk)
                on_chunk(chunk)
            return len(data)

        with patch.object(client, "stream_file", side_effect=stream):
            result = pull_file(client, "/private/source", self.target)
        self.assertEqual(result.sha256, client.before.sha256)
        self.assertEqual(self.target.read_bytes(), data)

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


class DirectoryTests(unittest.TestCase):
    """Verify archive extraction and publication only after batch verification."""

    def setUp(self) -> None:
        """Create an isolated destination and a tree of controlled source files."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.entries = [
            DirectoryEntry(".hidden", False), DirectoryEntry("empty", True),
            DirectoryEntry("sub folder", True), DirectoryEntry("zero", False),
            DirectoryEntry("sub folder/空 格 ' $; `id`.bin", False),
        ]
        self.files = {
            "/private/source/.hidden": FixtureClient(b"hidden"),
            "/private/source/zero": FixtureClient(b""),
            "/private/source/sub folder/空 格 ' $; `id`.bin": FixtureClient(bytes(range(256))),
        }
        self.stream_calls = 0
        self.stream_failure: BaseException | None = None
        self.archive_override: bytes | None = None
        self.client = SimpleNamespace(
            path_kind=lambda remote: "directory",
            list_directory=lambda remote: self.entries,
            inspect_file_later=lambda remote: self.files[remote].inspect_file_later(remote),
            inspect_file=lambda remote: self.files[remote].inspect_file(remote),
            stream_file=lambda remote, *args: self.files[remote].stream_file(remote, *args),
            stream_directory=self._stream_directory,
        )

    def _archive(self) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            for entry in self.entries:
                member = tarfile.TarInfo("./" + entry.path)
                if entry.is_dir:
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                else:
                    data = self.files["/private/source/" + entry.path].data
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        return gzip.compress(output.getvalue())

    @contextmanager
    def _stream_directory(self, remote, on_chunk):
        self.stream_calls += 1
        payload = self._archive() if self.archive_override is None else self.archive_override
        on_chunk(payload)
        with io.BytesIO(payload) as source:
            yield source
        if self.stream_failure:
            raise self.stream_failure

    def test_recursive_download(self) -> None:
        """Auto-detect a folder and preserve hidden, empty and nested entries."""
        stages = []
        updates = []
        result = pull(self.client, "/private/source/", self.root,
                      progress=lambda copied, total: updates.append((copied, total)),
                      stage=stages.append)
        self.assertIsInstance(result, DirectoryPullResult)
        self.assertEqual(result.destination, self.root / "source")
        self.assertEqual(result.file_count, 3)
        self.assertEqual(result.size, 262)
        self.assertTrue((result.destination / "empty").is_dir())
        for remote, client in self.files.items():
            self.assertEqual((result.destination / remote.removeprefix("/private/source/")).read_bytes(), client.data)
            self.assertEqual(client.inspections, 0)
        self.assertEqual(self.stream_calls, 1)
        self.assertLess(len(stages), 6)
        self.assertEqual(updates[-1], (len(self._archive()), 0))
        self.assertEqual(list(self.root.rglob("*.part")), [])

    def test_new_destination_and_empty_source(self) -> None:
        """Create an explicit destination, including for an entirely empty tree."""
        self.entries.clear()
        target = self.root / "new" / "renamed"
        result = pull_directory(self.client, "/private/source", target)
        self.assertEqual(result, DirectoryPullResult(target, 0, 0))
        self.assertTrue(target.is_dir())

    def test_default_destination(self) -> None:
        """Use the source basename in the current directory when local is omitted."""
        self.entries.clear()
        with patch("adb_puller.transfer.Path.cwd", return_value=self.root):
            result = pull_directory(self.client, "/private/source/.")
        self.assertEqual(result.destination, self.root / "source")

    def test_overwrite_merges_without_removing_unrelated_files(self) -> None:
        """Reject an existing tree by default and merge verified files on request."""
        target = self.root / "source"
        target.mkdir()
        (target / ".hidden").write_bytes(b"old")
        (target / "unrelated").write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            pull_directory(self.client, "/private/source", self.root)
        self.assertEqual((target / ".hidden").read_bytes(), b"old")
        result = pull_directory(self.client, "/private/source", self.root, overwrite=True)
        self.assertEqual(result.file_count, 3)
        self.assertEqual((target / ".hidden").read_bytes(), b"hidden")
        self.assertEqual((target / "unrelated").read_bytes(), b"keep")

    def test_destination_type_conflict_before_copying(self) -> None:
        """Preflight every entry so late file/directory conflicts copy no data."""
        target = self.root / "source"
        (target / "sub folder" / "空 格 ' $; `id`.bin").mkdir(parents=True)
        with self.assertRaises(IsADirectoryError):
            pull_directory(self.client, "/private/source", self.root, overwrite=True)
        self.assertFalse((target / ".hidden").exists())
        self.assertTrue(all(client.inspections == 0 for client in self.files.values()))

    def test_hash_failure_preserves_entire_existing_tree(self) -> None:
        """Reject the whole staged download when the final archive hash fails."""
        target = self.root / "source"
        (target / "sub folder").mkdir(parents=True)
        failed = target / "sub folder" / "空 格 ' $; `id`.bin"
        failed.write_bytes(b"old")
        (target / ".hidden").write_bytes(b"old hidden")
        self.stream_failure = AdbError("archive SHA-256 mismatch")
        with self.assertRaisesRegex(AdbError, "SHA-256"):
            pull_directory(self.client, "/private/source", self.root, overwrite=True)
        self.assertEqual((target / ".hidden").read_bytes(), b"old hidden")
        self.assertEqual(failed.read_bytes(), b"old")
        self.assertEqual(list(self.root.rglob("*.part")), [])

    def test_invalid_local_names_before_creating_tree(self) -> None:
        """Reject escaping paths and names that cannot map to distinct local files."""
        names = ["../escape", "/absolute"]
        if os.name == "nt":
            names += ["CON", "bad:name", "trailing.", "sub\\escape", "line\nbreak"]
        for name in names:
            with self.subTest(name=name):
                self.entries[:] = [DirectoryEntry(name, False)]
                with self.assertRaises(AdbError):
                    pull_directory(self.client, "/private/source", self.root)
                self.assertFalse((self.root / "source").exists())
        self.entries[:] = [DirectoryEntry("same", False), DirectoryEntry("same", True)]
        with self.assertRaises(AdbError):
            pull_directory(self.client, "/private/source", self.root)
        if os.name == "nt":
            self.entries[:] = [DirectoryEntry("same", False), DirectoryEntry("SAME", False)]
            with self.assertRaises(AdbError):
                pull_directory(self.client, "/private/source", self.root)

    def test_cancellation_removes_staged_tree(self) -> None:
        """Discard extracted files when cancellation happens before publication."""
        self.stream_failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            pull_directory(self.client, "/private/source", self.root)
        self.assertFalse((self.root / "source").exists())
        self.assertEqual(list(self.root.rglob("*.part")), [])

    def test_local_directory_link_is_rejected(self) -> None:
        """Refuse an existing directory link that would redirect a child write."""
        target = self.root / "source"
        target.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        link = target / "sub folder"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlinks requires additional host privileges")
        with self.assertRaises(AdbError):
            pull_directory(self.client, "/private/source", self.root, overwrite=True)
        self.assertEqual(list(outside.iterdir()), [])

    def test_corrupt_or_truncated_archive(self) -> None:
        """Discard staged output on gzip CRC errors or a missing archive tail."""
        payload = self._archive()
        corrupt = payload[:-8] + bytes([payload[-8] ^ 1]) + payload[-7:]
        for data in (payload[:-20], corrupt):
            with self.subTest(length=len(data)):
                self.archive_override = data
                with self.assertRaises(AdbError):
                    pull_directory(self.client, "/private/source", self.root)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_archive_inventory_mismatch(self) -> None:
        """Reject missing or newly added files before publishing any contents."""
        original = self.entries.copy()
        self.entries.pop()
        self.archive_override = self._archive()
        self.entries[:] = original
        with self.assertRaises(AdbError):
            pull_directory(self.client, "/private/source", self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_destination_created_during_download(self) -> None:
        """Preserve a directory another process creates while streaming."""
        target = self.root / "source"

        def progress(copied, total):
            target.mkdir()
            (target / "concurrent").write_bytes(b"keep")

        with self.assertRaises(FileExistsError):
            pull_directory(self.client, "/private/source", self.root, progress=progress)
        self.assertEqual([path.name for path in target.iterdir()], ["concurrent"])
        self.assertEqual(list(self.root.rglob("*.part")), [])

    def test_unsafe_archive_entries(self) -> None:
        """Reject traversal, symlinks and hardlinks outside the staged inventory."""
        for name, kind, link in (
            ("../escape", tarfile.REGTYPE, ""),
            ("/absolute", tarfile.REGTYPE, ""),
            (".hidden", tarfile.SYMTYPE, "../../escape"),
            (".hidden", tarfile.LNKTYPE, "../../escape"),
        ):
            with self.subTest(name=name, kind=kind):
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w") as archive:
                    member = tarfile.TarInfo(name)
                    member.type, member.linkname = kind, link
                    archive.addfile(member)
                self.archive_override = output.getvalue()
                with self.assertRaises(AdbError):
                    pull_directory(self.client, "/private/source", self.root)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_raw_tar_and_hardlinks(self) -> None:
        """Copy an internal hardlink as regular bytes without requiring host links."""
        self.entries[:] = [DirectoryEntry("first", False), DirectoryEntry("second", False)]
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            member = tarfile.TarInfo("./first")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"data"))
            member = tarfile.TarInfo("./second")
            member.type, member.linkname = tarfile.LNKTYPE, "./first"
            archive.addfile(member)
        self.archive_override = output.getvalue()
        result = pull_directory(self.client, "/private/source", self.root)
        self.assertEqual(result.size, 8)
        self.assertEqual(result.file_count, 2)
        self.assertEqual((result.destination / "second").read_bytes(), b"data")

    def test_file_auto_detection(self) -> None:
        """Keep file pulls and their result unchanged through the common entry."""
        client = self.files["/private/source/.hidden"]
        client.path_kind = lambda remote: "file"
        result = pull(client, "/private/source/.hidden", self.root)
        self.assertEqual(result.sha256, client.before.sha256)
        self.assertEqual(result.destination.read_bytes(), b"hidden")
