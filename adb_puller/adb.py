"""Run binary-safe ADB commands and inspect files through Android su."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import io
from queue import Empty, Full, Queue
import re
import shlex
import subprocess
import tempfile
from threading import Event
from typing import BinaryIO, Callable, Iterator
import zlib


_BLOCK_SIZE = 1024 * 1024
_CHUNK_SIZE = 4 * _BLOCK_SIZE
_ARCHIVE_MARKER = b"\nADB_PULLER_ARCHIVE_OK\n"
_ARCHIVE_FOOTER_SIZE = 1 + 64 + len(_ARCHIVE_MARKER)


class AdbError(RuntimeError):
    """Report an ADB, root-access, or remote integrity failure."""


@dataclass(frozen=True)
class FileInfo:
    """Record a remote regular file's size and identity from Android stat."""

    size: int
    mtime: int
    ctime: int
    inode: int
    device: int


@dataclass(frozen=True)
class Snapshot:
    """Associate stable remote file metadata with its SHA-256 digest."""

    info: FileInfo
    sha256: str


@dataclass(frozen=True)
class DirectoryEntry:
    """Describe a relative remote path and whether it is a directory."""

    path: str
    is_dir: bool


class _ArchiveReader(io.RawIOBase):
    """Strip and verify a trailing SHA-256 frame while exposing archive bytes."""

    def __init__(
        self, receive: Callable[[], bytes | None], on_chunk: Callable[[bytes], None],
    ) -> None:
        super().__init__()
        self.receive = receive
        self.on_chunk = on_chunk
        self.tail = b""
        self.buffer = b""
        self.offset = 0
        self.digest = hashlib.sha256()
        self.ended = False

    def readable(self) -> bool:
        """Return whether this archive stream supports binary reads."""
        return True

    def readinto(self, target) -> int:
        """Fill target with archive bytes, validating the sender's hash at EOF."""
        if not len(target):
            return 0
        while not self.buffer and not self.ended:
            chunk = self.receive()
            if chunk is None:
                if (
                    len(self.tail) != _ARCHIVE_FOOTER_SIZE
                    or not self.tail.startswith(b"\n")
                    or not self.tail.endswith(_ARCHIVE_MARKER)
                    or not re.fullmatch(b"[0-9a-f]{64}", self.tail[1:65])
                ):
                    raise AdbError("目錄打包串流不完整，未收到有效的 SHA-256 完成標記。")
                if self.tail[1:65].decode("ascii") != self.digest.hexdigest():
                    raise AdbError("目錄打包串流 SHA-256 不一致。")
                self.ended = True
                break
            # Binary payloads may contain marker bytes. Keep a fixed-size tail
            # until EOF rather than searching the archive for a delimiter.
            self.tail += chunk
            if len(self.tail) > _ARCHIVE_FOOTER_SIZE:
                self.buffer = self.tail[:-_ARCHIVE_FOOTER_SIZE]
                self.tail = self.tail[-_ARCHIVE_FOOTER_SIZE:]
                self.digest.update(self.buffer)
                self.on_chunk(self.buffer)
        size = min(len(target), len(self.buffer) - self.offset)
        target[:size] = self.buffer[self.offset:self.offset + size]
        self.offset += size
        if self.offset == len(self.buffer):
            self.buffer = b""
            self.offset = 0
        return size


@dataclass(frozen=True)
class _Inspection:
    """Expose initial metadata while a cancellable remote hash runs."""

    info: FileInfo
    _resolve: Callable[[], Snapshot]
    _ready: Callable[[], bool]

    def done(self) -> bool:
        """Return whether the remote hash command has exited, successfully or not."""
        return self._ready()

    def result(self) -> Snapshot:
        """Wait for the hash and return a snapshot stable since inspection began."""
        return self._resolve()


class AdbClient:
    """Access one device using an adb executable and optional device serial."""

    def __init__(
        self,
        adb: str = "adb",
        serial: str | None = None,
        *,
        jobs: int = 4,
        compression: str = "auto",
    ) -> None:
        """Configure ADB, serial, 1–8 transfer jobs, and auto/gzip/none compression."""
        if not 1 <= jobs <= 8:
            raise ValueError("jobs 必須介於 1 到 8。")
        if compression not in ("auto", "gzip", "none"):
            raise ValueError("compression 必須是 auto、gzip 或 none。")
        self.adb = adb
        self.serial = serial
        self.jobs = jobs
        self.compression = compression

    def _command(self, *arguments: str) -> list[str]:
        command = [self.adb]
        if self.serial:
            command.extend(["-s", self.serial])
        return [*command, *arguments]

    def devices(self) -> str:
        """Return adb's device listing, including authorization and serials."""
        return self._run(self._command("devices", "-l"), timeout=30).decode(
            "utf-8", errors="replace"
        )

    @staticmethod
    def _run(command: list[str], timeout: float | None) -> bytes:
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise AdbError("ADB 指令逾時；請確認手機連線與 root 授權。") from error
        if result.returncode:
            detail = (result.stderr + result.stdout).decode("utf-8", errors="replace").strip()
            raise AdbError(detail or f"ADB 指令失敗（結束碼 {result.returncode}）。")
        return result.stdout

    def _root_command(self, script: str) -> list[str]:
        # ADB joins remote arguments before invoking the Android shell. Quote the
        # entire su script as one remote argument, independently of the host shell.
        return self._command("exec-out", f"su -c {shlex.quote(script)}")

    def _control(self, script: str, timeout: float | None = 30) -> str:
        output = self._run(self._root_command(script), timeout)
        return self._parse_control(output)

    @staticmethod
    def _parse_control(output: bytes) -> str:
        try:
            lines = output.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise AdbError("root 指令回傳無法辨識的內容。") from error
        # The exec service can lose the remote exit status. Require an explicit
        # success marker and an exact response shape before trusting metadata.
        if len(lines) != 2 or lines[-1] != "ADB_PULLER_OK":
            detail = output[:4096].decode("utf-8", errors="replace").strip()
            raise AdbError(f"無法讀取 root 檔案資訊：{detail or '沒有有效回應'}")
        return lines[0]

    def _stat(self, remote: str) -> FileInfo:
        quoted = shlex.quote(remote)
        output = self._control(
            'test "$(id -u)" = 0 || { echo "需要 su root 權限" >&2; exit 1; }; '
            f"test -f {quoted} || {{ echo '來源不存在或不是一般檔案' >&2; exit 1; }}; "
            f"stat -L -c '%s %Y %Z %i %d' -- {quoted} && printf 'ADB_PULLER_OK\\n'"
        )
        if not re.fullmatch(r"\d+ -?\d+ -?\d+ \d+ \d+", output):
            raise AdbError(f"無法解析遠端 stat 回應：{output!r}")
        return FileInfo(*(int(value) for value in output.split()))

    @staticmethod
    def _validate_remote(remote: str) -> None:
        if not remote.startswith("/") or "\0" in remote:
            raise AdbError("手機來源必須是絕對路徑，且不能包含 NUL 字元。")

    def path_kind(self, remote: str) -> str:
        """Return 'file' or 'directory' for an absolute remote path using root."""
        self._validate_remote(remote)
        quoted = shlex.quote(remote)
        kind = self._control(
            'test "$(id -u)" = 0 || { echo "需要 su root 權限" >&2; exit 1; }; '
            f"if test -d {quoted}; then echo directory; "
            f"elif test -f {quoted}; then echo file; "
            "else echo '來源不存在或不是一般檔案／目錄' >&2; exit 1; fi; "
            "printf 'ADB_PULLER_OK\\n'"
        )
        if kind not in ("file", "directory"):
            raise AdbError(f"無法辨識來源類型：{kind!r}")
        return kind

    def list_directory(self, remote: str) -> list[DirectoryEntry]:
        """List all descendants, including hidden and empty directories, using root.

        Return relative paths in parent-first order. Reject symlinks and special
        files rather than following links outside the requested directory.
        """
        self._validate_remote(remote)
        # NUL-delimited type/path pairs preserve spaces, quotes and newlines.
        # Batch the shell classification so find does not spawn once per entry.
        classify = (
            'for path; do '
            'if test -L "$path"; then kind=x; '
            'elif test -d "$path"; then kind=d; '
            'elif test -f "$path"; then kind=f; else kind=x; fi; '
            'printf "%s\\000%s\\000" "$kind" "$path"; done'
        )
        script = (
            'test "$(id -u)" = 0 || { echo "需要 su root 權限" >&2; exit 1; }; '
            f"cd -- {shlex.quote(remote)} && "
            f"find . -exec sh -c {shlex.quote(classify)} sh {{}} + && "
            "printf 'ADB_PULLER_OK\\000'"
        )
        output = self._run(self._root_command(script), timeout=None)
        try:
            fields = output.decode("utf-8").split("\0")
        except UnicodeDecodeError as error:
            raise AdbError("目錄包含無法以 UTF-8 辨識的檔名。") from error
        if fields[-2:] != ["ADB_PULLER_OK", ""] or len(fields) % 2:
            raise AdbError("無法完整讀取 root 目錄清單；請確認連線、root 與 find 指令。")
        entries: dict[str, bool] = {}
        for kind, path in zip(fields[:-2:2], fields[1:-2:2]):
            if kind not in ("d", "f"):
                raise AdbError(f"資料夾包含符號連結或特殊檔案，無法拉取：{path!r}")
            if path != "." and (
                not path.startswith("./")
                or any(part in ("", ".", "..") for part in path[2:].split("/"))
            ):
                raise AdbError(f"無法辨識目錄中的相對路徑：{path!r}")
            if path in entries:
                raise AdbError(f"目錄清單包含重複路徑：{path!r}")
            entries[path] = kind == "d"
        if entries.pop(".", None) is not True:
            raise AdbError("目錄清單缺少來源目錄。")
        for path in entries:
            parent = path.rsplit("/", 1)[0]
            if parent != "." and entries.get(parent) is not True:
                raise AdbError(f"目錄清單缺少父目錄：{path!r}")
        return [DirectoryEntry(path[2:], is_dir) for path, is_dir in sorted(
            entries.items(), key=lambda item: (item[0].count("/"), item[0])
        )]

    def _directory_script(self, remote: str) -> str:
        # Only the FIFO, digest and success flags live on the phone. Status
        # flags catch failures in every pipeline stage without relying on the
        # remote shell's pipefail support or ADB's remote exit-status forwarding.
        return (
            'test "$(id -u)" = 0 || { echo "需要 su root 權限" >&2; exit 1; }; '
            'for tool in tar tee mkfifo mktemp sha256sum; do '
            'command -v "$tool" >/dev/null 2>&1 || '
            '{ echo "目錄串流缺少工具：$tool" >&2; exit 1; }; done; '
            f"compression={shlex.quote(self.compression)}; "
            'if test "$compression" != none; then '
            'if command -v gzip >/dev/null 2>&1; then compression=gzip; '
            'elif test "$compression" = gzip; then '
            'echo "手機沒有 gzip；請改用 --compression none。" >&2; exit 1; '
            'else compression=none; fi; fi; '
            f"cd -- {shlex.quote(remote)} || exit 1; "
            'umask 077; work=$(mktemp -d /data/local/tmp/adb-puller-stream.XXXXXXXXXX) || exit 1; '
            'source_root=$(pwd -P); exclude=; '
            'case "$work" in "${source_root%/}/"*) exclude="./${work#"${source_root%/}/"}" ;; esac; '
            'hash_pid=; '
            'cleanup() { '
            'if test -n "$hash_pid"; then kill "$hash_pid" 2>/dev/null; wait "$hash_pid" 2>/dev/null; fi; '
            'rm -f -- "$work/hash" "$work/digest" "$work/tar.ok" "$work/filter.ok"; '
            'rmdir -- "$work"; }; '
            "trap cleanup EXIT; trap 'exit 1' HUP INT TERM; "
            'mkfifo "$work/hash" || exit 1; '
            'sha256sum < "$work/hash" > "$work/digest" & hash_pid=$!; '
            '{ if test -n "$exclude"; then tar --exclude "$exclude" -cf - .; '
            'else tar -cf - .; fi && echo ok > "$work/tar.ok"; } | '
            '{ if test "$compression" = gzip; then gzip -1 -c; else cat; fi '
            '&& echo ok > "$work/filter.ok"; } | tee "$work/hash" || exit 1; '
            'wait "$hash_pid" || exit 1; hash_pid=; '
            'test -f "$work/tar.ok" && test -f "$work/filter.ok" || exit 1; '
            'read -r digest rest < "$work/digest" || exit 1; '
            "printf '\\n%s\\nADB_PULLER_ARCHIVE_OK\\n' \"$digest\""
        )

    @contextmanager
    def stream_directory(
        self, remote: str, on_chunk: Callable[[bytes], None],
    ) -> Iterator[BinaryIO]:
        """Yield one tar/gzip stream and verify its SHA-256 on context success.

        remote must be absolute. on_chunk receives transferred archive bytes,
        before decompression. Buffering is bounded; exit reaps the ADB child,
        including when extraction or the progress callback fails.
        """
        self._validate_remote(remote)
        events: Queue[bytes | BaseException | None] = Queue(maxsize=2)
        stopped = Event()

        def send(event: bytes | BaseException | None) -> None:
            while not stopped.is_set():
                try:
                    events.put(event, timeout=0.1)
                    return
                except Full:
                    pass

        def receive() -> bytes | None:
            while True:
                try:
                    event = events.get(timeout=0.1)
                except Empty:
                    continue
                if isinstance(event, BaseException):
                    raise event
                return event

        with tempfile.TemporaryFile() as diagnostics:
            process = subprocess.Popen(
                self._root_command(self._directory_script(remote)),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=diagnostics,
            )
            assert process.stdout is not None

            def pump() -> None:
                try:
                    while not stopped.is_set():
                        chunk = process.stdout.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        send(chunk)
                    if stopped.is_set():
                        return
                    if process.wait():
                        diagnostics.seek(0)
                        detail = diagnostics.read(65536).decode("utf-8", errors="replace").strip()
                        raise AdbError(detail or "手機目錄打包或傳輸失敗。")
                    send(None)
                except BaseException as error:
                    send(error)

            executor = ThreadPoolExecutor(max_workers=1)
            reader = _ArchiveReader(receive, on_chunk)
            try:
                executor.submit(pump)
                yield reader
                # Tar readers can stop at the end-of-archive blocks, before
                # the sender's footer. Always drain to EOF to verify the hash.
                while reader.read(_CHUNK_SIZE):
                    pass
            finally:
                stopped.set()
                if process.poll() is None:
                    process.kill()
                process.wait()
                executor.shutdown(wait=True)
                process.stdout.close()
                reader.close()

    def inspect_file(self, remote: str) -> Snapshot:
        """Return metadata and SHA-256 for an absolute path stable during hashing."""
        with self.inspect_file_later(remote) as inspection:
            return inspection.result()

    @contextmanager
    def inspect_file_later(self, remote: str) -> Iterator[_Inspection]:
        """Yield initial metadata immediately and hash an absolute remote path.

        Call result() inside the context to wait for a stable SHA-256 snapshot.
        Leaving the context reaps the ADB process, including on cancellation.
        """
        self._validate_remote(remote)
        before = self._stat(remote)
        # Hash stdin so unusual filenames never enter sha256sum's output format.
        script = (
            f"digest=$(sha256sum < {shlex.quote(remote)}) || exit 1; "
            'printf \'%s\\nADB_PULLER_OK\\n\' "${digest%% *}"'
        )
        with tempfile.TemporaryFile() as diagnostics:
            process = subprocess.Popen(
                self._root_command(script),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=diagnostics,
            )
            snapshot: Snapshot | None = None

            def resolve() -> Snapshot:
                nonlocal snapshot
                if snapshot is not None:
                    return snapshot
                output, _ = process.communicate()
                if process.returncode:
                    diagnostics.seek(0)
                    detail = (diagnostics.read(65536) + output).decode(
                        "utf-8", errors="replace"
                    ).strip()
                    raise AdbError(detail or f"ADB 雜湊計算失敗（結束碼 {process.returncode}）。")
                digest = self._parse_control(output)
                if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                    raise AdbError("手機未回傳有效的 SHA-256；請確認 sha256sum 可用。")
                if self._stat(remote) != before:
                    raise AdbError("計算 SHA-256 時來源檔案已變動；請停止寫入該檔案後重試。")
                snapshot = Snapshot(before, digest.lower())
                return snapshot

            try:
                yield _Inspection(before, resolve, lambda: process.poll() is not None)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                assert process.stdout is not None
                process.stdout.close()

    def _transfer_options(self, remote: str, size: int) -> tuple[int, bool]:
        # Avoid multiple su startups for small files; each worker gets at least
        # 8 MiB. Block-aligned ranges let Android's portable dd seek directly.
        jobs = min(self.jobs, max(1, size // (8 * _BLOCK_SIZE)))
        if self.compression == "none" and jobs == 1:
            return 1, False
        available = self._control(
            "printf '%s %s\\nADB_PULLER_OK\\n' "
            '"$(command -v dd >/dev/null 2>&1 && echo dd)" '
            '"$(command -v gzip >/dev/null 2>&1 && echo gzip)"'
        ).split()
        if "dd" not in available:
            jobs = 1
        if self.compression == "gzip":
            if "gzip" not in available:
                raise AdbError("手機沒有 gzip；請改用 --compression none。")
            return jobs, True
        if self.compression == "none" or not {"dd", "gzip"}.issubset(available) or not size:
            return jobs, False
        # Sample in memory instead of creating a compressed copy on the phone.
        # Incompressible archives/media keep the original binary transfer path.
        sample = self._run(
            self._root_command(f"dd if={shlex.quote(remote)} bs=65536 count=4 2>/dev/null"),
            timeout=30,
        )
        compressed = bool(sample) and len(zlib.compress(sample, 1)) < len(sample) * 0.9
        return jobs, compressed

    @staticmethod
    def _ranges(size: int, jobs: int) -> list[tuple[int, int]]:
        blocks = (size + _BLOCK_SIZE - 1) // _BLOCK_SIZE
        span = max(1, (blocks + jobs - 1) // jobs) * _BLOCK_SIZE
        return [(start, min(span, size - start)) for start in range(0, size, span)] or [(0, 0)]

    def stream_file(
        self,
        remote: str,
        destination: BinaryIO,
        expected_size: int,
        on_chunk: Callable[[bytes], None],
    ) -> int:
        """Write remote ranges and return the uncompressed byte count.

        destination must support seeking when multiple jobs are used. on_chunk
        receives bytes in arrival order for progress; hash the completed file
        to obtain a digest in file order.
        """
        jobs, compressed = self._transfer_options(remote, expected_size)
        ranges = self._ranges(expected_size, jobs)
        events: Queue[tuple[int, bytes] | BaseException | None] = Queue(maxsize=2 * len(ranges))
        stopped = Event()

        def send(event: tuple[int, bytes] | BaseException | None) -> None:
            while not stopped.is_set():
                try:
                    events.put(event, timeout=0.1)
                    return
                except Full:
                    pass

        def receive(process, diagnostics, start: int, length: int) -> None:
            received = 0
            decoder = zlib.decompressobj(wbits=31) if compressed else None

            def deliver(chunk: bytes) -> None:
                nonlocal received
                if received + len(chunk) > length:
                    raise AdbError("收到的資料超過來源大小；來源可能已變動或 root 輸出受到干擾。")
                if chunk:
                    send((start + received, chunk))
                    received += len(chunk)

            try:
                while not stopped.is_set():
                    chunk = process.stdout.read(256 * 1024 if decoder else _CHUNK_SIZE)
                    if not chunk:
                        break
                    if decoder:
                        while chunk and not stopped.is_set():
                            deliver(decoder.decompress(chunk, _CHUNK_SIZE))
                            if decoder.unused_data:
                                raise AdbError("gzip 串流含有多餘資料。")
                            chunk = decoder.unconsumed_tail
                    else:
                        deliver(chunk)
                if stopped.is_set():
                    return
                returncode = process.wait()
                diagnostics.seek(0)
                detail = diagnostics.read(65536).decode("utf-8", errors="replace").strip()
                if returncode:
                    raise AdbError(detail or f"ADB 傳輸失敗（結束碼 {returncode}）。")
                if decoder and not decoder.eof:
                    raise AdbError("gzip 串流不完整。")
                if received != length:
                    raise AdbError(
                        f"傳輸不完整：預期 {length} bytes，收到 {received} bytes。"
                        + (f" {detail}" if detail else "")
                    )
                send(None)
            except zlib.error as error:
                send(AdbError(f"gzip 串流損毀：{error}"))
            except BaseException as error:
                send(error)

        processes: list[subprocess.Popen] = []
        copied = 0
        with ExitStack() as resources:
            executor = ThreadPoolExecutor(max_workers=len(ranges))
            try:
                for start, length in ranges:
                    diagnostics = resources.enter_context(tempfile.TemporaryFile())
                    if len(ranges) == 1:
                        script = f"cat -- {shlex.quote(remote)}"
                    else:
                        script = (
                            f"dd if={shlex.quote(remote)} bs={_BLOCK_SIZE} "
                            f"skip={start // _BLOCK_SIZE} "
                            f"count={(length + _BLOCK_SIZE - 1) // _BLOCK_SIZE} 2>/dev/null"
                        )
                    if compressed:
                        # stdin redirection preserves the source even for gzip
                        # implementations whose default file mode removes input.
                        if len(ranges) == 1:
                            script = f"exec gzip -1 -c < {shlex.quote(remote)}"
                        else:
                            script += " | gzip -1 -c"
                    else:
                        script = "exec " + script
                    process = subprocess.Popen(
                        self._root_command(script),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=diagnostics,
                    )
                    processes.append(process)
                    assert process.stdout is not None
                    executor.submit(receive, process, diagnostics, start, length)

                finished = 0
                while finished < len(ranges):
                    # A bounded wait lets Windows deliver Ctrl+C even when no
                    # worker currently has data, such as during a disconnect.
                    try:
                        event = events.get(timeout=0.1)
                    except Empty:
                        continue
                    if event is None:
                        finished += 1
                    elif isinstance(event, BaseException):
                        raise event
                    else:
                        offset, chunk = event
                        if len(ranges) > 1:
                            destination.seek(offset)
                        destination.write(chunk)
                        copied += len(chunk)
                        on_chunk(chunk)
                return copied
            finally:
                # Kill before joining: blocked pipe reads and full queues must
                # both unblock when a write, callback, or process startup fails.
                stopped.set()
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                for process in processes:
                    process.wait()
                executor.shutdown(wait=True)
                for process in processes:
                    process.stdout.close()
