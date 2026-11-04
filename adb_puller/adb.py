"""Run binary-safe ADB commands and inspect files through Android su."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import io
import os
from queue import Empty, Full, Queue
import re
import shlex
import subprocess
import tempfile
from threading import Event, Lock
from typing import BinaryIO, Callable, Iterator
import zlib


_BLOCK_SIZE = 1024 * 1024
_CHUNK_SIZE = 4 * _BLOCK_SIZE
_PIPE_SIZE = 1024 * 1024
_ARCHIVE_MARKER = b"\nADB_PULLER_ARCHIVE_OK\n"
_HASH_COMMANDS = {
    "crc32": ("crc32", "toybox crc32", "busybox crc32"),
    "md5": ("md5sum",),
}
# One su call learns the fastest checksum the phone can actually compute.
# "123456789" is the CRC-32 check vector (0xCBF43926); a different applet is ignored.
_PROBE_SCRIPT = (
    'test "$(id -u)" = 0 || { echo "需要 su root 權限" >&2; exit 1; }; '
    "try_crc() { "
    'out=$(printf 123456789 | "$@" 2>/dev/null) || return 1; '
    "set -- $out; "
    "case $1 in cbf43926|CBF43926) return 0 ;; esac; "
    "return 1; }; "
    "hash_alg=; hash_cmd=; "
    "if command -v crc32 >/dev/null 2>&1 && try_crc crc32; then "
    "hash_alg=crc32; hash_cmd=crc32; "
    "elif command -v toybox >/dev/null 2>&1 && try_crc toybox crc32; then "
    "hash_alg=crc32; hash_cmd='toybox crc32'; "
    "elif command -v busybox >/dev/null 2>&1 && try_crc busybox crc32; then "
    "hash_alg=crc32; hash_cmd='busybox crc32'; "
    "elif command -v md5sum >/dev/null 2>&1; then hash_alg=md5; hash_cmd=md5sum; "
    "else echo '手機缺少 crc32 與 md5sum，無法校驗傳輸。' >&2; exit 1; fi; "
    "dd_ok=$(command -v dd >/dev/null 2>&1 && printf dd); "
    "gzip_ok=$(command -v gzip >/dev/null 2>&1 && printf gzip); "
    "printf '%s\\t%s\\t%s\\t%s\\nADB_PULLER_OK\\n' "
    '"$hash_alg" "$hash_cmd" "$dd_ok" "$gzip_ok"'
)


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
    """Associate stable remote file metadata with its integrity digest."""

    info: FileInfo
    digest: str
    algorithm: str


def hash_label(algorithm: str) -> str:
    """Return the Traditional Chinese label for a transfer checksum algorithm."""
    return {"crc32": "CRC-32", "md5": "MD5"}.get(algorithm, algorithm)


def _hex_length(algorithm: str) -> int:
    if algorithm == "crc32":
        return 8
    if algorithm == "md5":
        return 32
    raise ValueError(f"不支援的校驗算法：{algorithm}")


def _footer_size(algorithm: str) -> int:
    return 1 + _hex_length(algorithm) + len(_ARCHIVE_MARKER)


class _Hasher:
    """Incrementally hash bytes with zlib CRC-32 or MD5."""

    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        self.length = 0
        self._crc = 0
        self._md5 = hashlib.md5() if algorithm == "md5" else None
        if algorithm not in _HASH_COMMANDS:
            raise ValueError(f"不支援的校驗算法：{algorithm}")

    def update(self, data: bytes) -> None:
        """Absorb the next contiguous chunk."""
        if data:
            if self._md5 is not None:
                self._md5.update(data)
            else:
                self._crc = zlib.crc32(data, self._crc) & 0xFFFFFFFF
            self.length += len(data)

    def hexdigest(self) -> str:
        """Return the lowercase digest of every byte absorbed so far."""
        if self._md5 is not None:
            return self._md5.hexdigest()
        return f"{self._crc:08x}"

    @property
    def crc(self) -> int:
        """Return the current zlib CRC-32 value."""
        return self._crc


def _gf2_matrix_times(matrix: list[int], vector: int) -> int:
    total = 0
    index = 0
    vector &= 0xFFFFFFFF
    while vector:
        if vector & 1:
            total ^= matrix[index]
        vector >>= 1
        index += 1
    return total & 0xFFFFFFFF


def _gf2_matrix_square(square: list[int], matrix: list[int]) -> None:
    for index in range(32):
        square[index] = _gf2_matrix_times(matrix, matrix[index])


def _crc32_combine(crc1: int, crc2: int, length2: int) -> int:
    """Return zlib CRC-32 of two concatenated blocks. length2 is the second length."""
    if length2 <= 0:
        return crc1 & 0xFFFFFFFF
    even = [0] * 32
    odd = [0] * 32
    odd[0] = 0xEDB88320
    row = 1
    for index in range(1, 32):
        odd[index] = row
        row <<= 1
    _gf2_matrix_square(even, odd)
    _gf2_matrix_square(odd, even)
    crc1 &= 0xFFFFFFFF
    while True:
        _gf2_matrix_square(even, odd)
        if length2 & 1:
            crc1 = _gf2_matrix_times(even, crc1)
        length2 >>= 1
        if length2 == 0:
            break
        _gf2_matrix_square(odd, even)
        if length2 & 1:
            crc1 = _gf2_matrix_times(odd, crc1)
        length2 >>= 1
        if length2 == 0:
            break
    return (crc1 ^ (crc2 & 0xFFFFFFFF)) & 0xFFFFFFFF


def _combine_crc32(parts: list[_Hasher]) -> str:
    """Combine in-order range CRC-32 values without rereading the file."""
    combined = 0
    started = False
    for part in parts:
        if part.length == 0:
            continue
        combined = part.crc if not started else _crc32_combine(combined, part.crc, part.length)
        started = True
    return f"{combined:08x}"


def file_digest(algorithm: str, data: bytes) -> str:
    """Return the lowercase transfer digest of a complete byte string."""
    hasher = _Hasher(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def hash_open_file(stream: BinaryIO, algorithm: str) -> str:
    """Hash an open binary file from the start and leave its position unchanged."""
    position = stream.tell()
    stream.seek(0)
    hasher = _Hasher(algorithm)
    try:
        while chunk := stream.read(_CHUNK_SIZE):
            hasher.update(chunk)
    finally:
        stream.seek(position)
    return hasher.hexdigest()


def _normalize_digest(algorithm: str, digest: str) -> str:
    digest = digest.strip().lower()
    if algorithm == "crc32":
        if not re.fullmatch(r"[0-9a-f]{1,8}", digest):
            raise AdbError("手機未回傳有效的 CRC-32。")
        return f"{int(digest, 16):08x}"
    if not re.fullmatch(r"[0-9a-f]{32}", digest):
        raise AdbError("手機未回傳有效的 MD5；請確認 md5sum 可用。")
    return digest


def _parse_capabilities(line: str) -> tuple[str, str, bool, bool]:
    parts = line.split("\t")
    if len(parts) != 4:
        raise AdbError(f"無法解析手機校驗工具：{line!r}")
    algorithm, command, dd_ok, gzip_ok = parts
    if command not in _HASH_COMMANDS.get(algorithm, ()):
        raise AdbError(f"無法解析手機校驗工具：{line!r}")
    return algorithm, command, dd_ok == "dd", gzip_ok == "gzip"


def _widen_pipe(stream: BinaryIO) -> None:
    """Raise the Linux pipe capacity so a fast reader is not limited to 64 KiB."""
    try:
        fileno = stream.fileno()
    except (AttributeError, OSError):
        return
    try:
        import fcntl
        fcntl.fcntl(fileno, 1031, _PIPE_SIZE)  # F_SETPIPE_SZ
    except (AttributeError, ImportError, OSError):
        return


def _popen_stream(command: list[str], diagnostics: BinaryIO) -> subprocess.Popen:
    """Start a binary child whose stdout pipe can hold 1 MiB.

    Windows anonymous pipes default to a few KiB. exec-out then stalls once the
    child fills that buffer, even when the reader asks for multi-megabyte chunks.
    """
    if os.name == "nt":
        try:
            return _popen_windows(command, diagnostics)
        except OSError:
            pass
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=diagnostics,
        bufsize=0,
    )
    assert process.stdout is not None
    _widen_pipe(process.stdout)
    return process


def _popen_windows(command: list[str], diagnostics: BinaryIO) -> subprocess.Popen:
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SecurityAttributes), wintypes.DWORD,
    ]
    kernel32.CreatePipe.restype = wintypes.BOOL
    kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel32.SetHandleInformation.restype = wintypes.BOOL

    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
    read_handle = wintypes.HANDLE()
    write_handle = wintypes.HANDLE()
    if not kernel32.CreatePipe(
        ctypes.byref(read_handle), ctypes.byref(write_handle), ctypes.byref(attributes), _PIPE_SIZE,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel32.SetHandleInformation(read_handle, 0x00000001, 0):
        raise ctypes.WinError(ctypes.get_last_error())

    read_fd = msvcrt.open_osfhandle(read_handle.value, os.O_RDONLY | os.O_BINARY)
    write_fd = msvcrt.open_osfhandle(write_handle.value, 0)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=write_fd,
            stderr=diagnostics,
            bufsize=0,
        )
    except Exception:
        os.close(read_fd)
        os.close(write_fd)
        raise
    try:
        os.close(write_fd)
    except OSError:
        pass
    process.stdout = open(read_fd, "rb", buffering=0)
    return process


@dataclass(frozen=True)
class DirectoryEntry:
    """Describe a relative remote path and whether it is a directory."""

    path: str
    is_dir: bool


class _ArchiveReader(io.RawIOBase):
    """Strip and verify a trailing checksum frame while exposing archive bytes."""

    def __init__(
        self,
        receive: Callable[[], bytes | None],
        on_chunk: Callable[[bytes], None],
        algorithm: str,
    ) -> None:
        super().__init__()
        self.receive = receive
        self.on_chunk = on_chunk
        self.algorithm = algorithm
        self.footer_size = _footer_size(algorithm)
        self.hex_length = _hex_length(algorithm)
        self.tail = b""
        self.buffer = b""
        self.offset = 0
        self.digest = _Hasher(algorithm)
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
                digest = self.tail[1:1 + self.hex_length]
                if (
                    len(self.tail) != self.footer_size
                    or not self.tail.startswith(b"\n")
                    or not self.tail.endswith(_ARCHIVE_MARKER)
                    or not re.fullmatch(rb"[0-9a-fA-F]{%d}" % self.hex_length, digest)
                ):
                    raise AdbError(
                        f"目錄打包串流不完整，未收到有效的 {hash_label(self.algorithm)} 完成標記。"
                    )
                if digest.decode("ascii").lower() != self.digest.hexdigest():
                    raise AdbError(f"目錄打包串流 {hash_label(self.algorithm)} 不一致。")
                self.ended = True
                break
            # Binary payloads may contain marker bytes. Keep a fixed-size tail
            # until EOF rather than searching the archive for a delimiter.
            self.tail += chunk
            if len(self.tail) > self.footer_size:
                self.buffer = self.tail[:-self.footer_size]
                self.tail = self.tail[-self.footer_size:]
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
        self._caps_lock = Lock()
        self._caps: tuple[str, str, bool, bool] | None = None

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

    def ensure_capabilities(self) -> tuple[str, str, bool, bool]:
        """Probe and cache the phone's fastest checksum plus dd/gzip availability.

        Prefer a zlib-compatible CRC-32 applet. Fall back to md5sum, which is
        still several times faster than sha256sum on toybox.
        """
        with self._caps_lock:
            if self._caps is None:
                self._caps = _parse_capabilities(self._control(_PROBE_SCRIPT))
            return self._caps

    @property
    def hash_algorithm(self) -> str:
        """Return the checksum algorithm selected for this device."""
        return self.ensure_capabilities()[0]

    @property
    def hash_command(self) -> str:
        """Return the remote command that hashes stdin with hash_algorithm."""
        return self.ensure_capabilities()[1]

    def file_info(self, remote: str) -> FileInfo:
        """Return size and identity for an absolute remote regular file."""
        self._validate_remote(remote)
        return self._stat(remote)

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
        # CRC-32/MD5 stays ahead of the pipe, so tee does not throttle tar/gzip.
        algorithm, command, _, _ = self.ensure_capabilities()
        width = _hex_length(algorithm)
        return (
            'test "$(id -u)" = 0 || { echo "需要 su root 權限" >&2; exit 1; }; '
            f"for tool in tar tee mkfifo mktemp {shlex.quote(command.split()[0])}; do "
            'command -v "$tool" >/dev/null 2>&1 || '
            '{ echo "目錄串流缺少工具：$tool" >&2; exit 1; }; done; '
            f"compression={shlex.quote(self.compression)}; "
            'if test "$compression" != none; then '
            'if command -v gzip >/dev/null 2>&1; then compression=gzip; '
            'elif test "$compression" = gzip; then '
            'echo "手機沒有 gzip；請改用 --compression none。" >&2; exit 1; '
            'else compression=none; fi; fi; '
            f"cd -- {shlex.quote(remote)} || exit 1; "
            'umask 077; work=$(mktemp -d /data/local/tmp/adb_puller-stream.XXXXXXXXXX) || exit 1; '
            'source_root=$(pwd -P); exclude=; '
            'case "$work" in "${source_root%/}/"*) exclude="./${work#"${source_root%/}/"}" ;; esac; '
            'hash_pid=; '
            'cleanup() { '
            'if test -n "$hash_pid"; then kill "$hash_pid" 2>/dev/null; wait "$hash_pid" 2>/dev/null; fi; '
            'rm -f -- "$work/hash" "$work/digest" "$work/tar.ok" "$work/filter.ok"; '
            'rmdir -- "$work"; }; '
            "trap cleanup EXIT; trap 'exit 1' HUP INT TERM; "
            'mkfifo "$work/hash" || exit 1; '
            f'{command} < "$work/hash" > "$work/digest" & hash_pid=$!; '
            '{ if test -n "$exclude"; then tar --exclude "$exclude" -cf - .; '
            'else tar -cf - .; fi && echo ok > "$work/tar.ok"; } | '
            '{ if test "$compression" = gzip; then gzip -1 -c; else cat; fi '
            '&& echo ok > "$work/filter.ok"; } | tee "$work/hash" || exit 1; '
            'wait "$hash_pid" || exit 1; hash_pid=; '
            'test -f "$work/tar.ok" && test -f "$work/filter.ok" || exit 1; '
            'read -r digest rest < "$work/digest" || exit 1; '
            f'while test ${{#digest}} -lt {width}; do digest=0$digest; done; '
            "printf '\\n%s\\nADB_PULLER_ARCHIVE_OK\\n' \"$digest\""
        )

    @contextmanager
    def stream_directory(
        self, remote: str, on_chunk: Callable[[bytes], None],
    ) -> Iterator[BinaryIO]:
        """Yield one tar/gzip stream and verify its checksum on context success.

        remote must be absolute. on_chunk receives transferred archive bytes,
        before decompression. Buffering is bounded; exit reaps the ADB child,
        including when extraction or the progress callback fails.
        """
        self._validate_remote(remote)
        events: Queue[bytes | BaseException | None] = Queue(maxsize=4)
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
            process = _popen_stream(self._root_command(self._directory_script(remote)), diagnostics)
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
            reader = _ArchiveReader(receive, on_chunk, self.hash_algorithm)
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
        """Return metadata and a fast digest for an absolute path stable during hashing."""
        with self.inspect_file_later(remote) as inspection:
            return inspection.result()

    @contextmanager
    def inspect_file_later(self, remote: str) -> Iterator[_Inspection]:
        """Yield initial metadata immediately and hash an absolute remote path.

        Call result() inside the context to wait for a stable checksum snapshot.
        Leaving the context reaps the ADB process, including on cancellation.
        """
        self._validate_remote(remote)
        algorithm = self.hash_algorithm
        label = hash_label(algorithm)
        before = self._stat(remote)
        # Hash stdin so unusual filenames never enter the digest line.
        script = (
            f"digest=$({self.hash_command} < {shlex.quote(remote)}) || exit 1; "
            "digest=${digest%% *}; "
            "printf '%s\\nADB_PULLER_OK\\n' \"$digest\""
        )
        with tempfile.TemporaryFile() as diagnostics:
            process = _popen_stream(self._root_command(script), diagnostics)
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
                digest = _normalize_digest(algorithm, self._parse_control(output))
                if self._stat(remote) != before:
                    raise AdbError(f"計算 {label} 時來源檔案已變動；請停止寫入該檔案後重試。")
                snapshot = Snapshot(before, digest, algorithm)
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
        _, _, has_dd, has_gzip = self.ensure_capabilities()
        if not has_dd:
            jobs = 1
        if self.compression == "gzip":
            if not has_gzip:
                raise AdbError("手機沒有 gzip；請改用 --compression none。")
            return jobs, True
        if self.compression == "none" or not (has_dd and has_gzip) or not size:
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
    ) -> tuple[int, str | None]:
        """Write remote ranges and return the uncompressed byte count and digest.

        destination must support seeking when multiple jobs are used. on_chunk
        receives bytes in arrival order for progress. CRC-32 is combined from
        each range as chunks arrive, so the caller does not reread the file.
        MD5 with more than one range cannot be combined; the digest is then None
        and the caller hashes the assembled file once.
        """
        algorithm = self.hash_algorithm
        jobs, compressed = self._transfer_options(remote, expected_size)
        ranges = self._ranges(expected_size, jobs)
        events: Queue[tuple[int, bytes] | BaseException | None] = Queue(maxsize=4 * len(ranges))
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
                    chunk = process.stdout.read(_CHUNK_SIZE)
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
        track = algorithm == "crc32" or len(ranges) == 1
        hashers = [_Hasher(algorithm) for _ in ranges] if track else []
        expected_offset = [start for start, _ in ranges]
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
                    process = _popen_stream(self._root_command(script), diagnostics)
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
                        index = next(
                            (
                                item for item, (start, length) in enumerate(ranges)
                                if start <= offset < start + length
                            ),
                            None,
                        )
                        if index is None or offset != expected_offset[index]:
                            raise AdbError("收到超出範圍或順序異常的資料區塊。")
                        expected_offset[index] = offset + len(chunk)
                        if track:
                            hashers[index].update(chunk)
                        if len(ranges) > 1:
                            destination.seek(offset)
                        destination.write(chunk)
                        copied += len(chunk)
                        on_chunk(chunk)
                if not track:
                    return copied, None
                if algorithm == "crc32":
                    return copied, _combine_crc32(hashers)
                return copied, hashers[0].hexdigest()
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
