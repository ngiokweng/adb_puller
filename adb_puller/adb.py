"""Run binary-safe ADB commands and inspect files through Android su."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
import tempfile
from typing import BinaryIO, Callable


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


class AdbClient:
    """Access one device using an adb executable and optional device serial."""

    def __init__(self, adb: str = "adb", serial: str | None = None) -> None:
        """Configure the adb executable and target serial; no connection is opened."""
        self.adb = adb
        self.serial = serial

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

    def inspect_file(self, remote: str) -> Snapshot:
        """Return metadata and SHA-256 for an absolute path stable during hashing."""
        if not remote.startswith("/") or "\0" in remote:
            raise AdbError("手機來源必須是絕對路徑，且不能包含 NUL 字元。")
        before = self._stat(remote)
        # Hash stdin so unusual filenames never enter sha256sum's output format.
        digest = self._control(
            f"digest=$(sha256sum < {shlex.quote(remote)}) || exit 1; "
            'printf \'%s\\nADB_PULLER_OK\\n\' "${digest%% *}"',
            timeout=None,
        )
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise AdbError("手機未回傳有效的 SHA-256；請確認 sha256sum 可用。")
        if self._stat(remote) != before:
            raise AdbError("計算 SHA-256 時來源檔案已變動；請停止寫入該檔案後重試。")
        return Snapshot(before, digest.lower())

    def stream_file(
        self,
        remote: str,
        destination: BinaryIO,
        expected_size: int,
        on_chunk: Callable[[bytes], None],
    ) -> int:
        """Write remote bytes to destination, call on_chunk, and return byte count."""
        copied = 0
        with tempfile.TemporaryFile() as diagnostics:
            process = subprocess.Popen(
                self._root_command(f"exec cat -- {shlex.quote(remote)}"),
                stdout=subprocess.PIPE,
                stderr=diagnostics,
            )
            assert process.stdout is not None
            try:
                while chunk := process.stdout.read(4 * 1024 * 1024):
                    if copied + len(chunk) > expected_size:
                        raise AdbError("收到的資料超過來源大小；來源可能已變動或 root 輸出受到干擾。")
                    destination.write(chunk)
                    copied += len(chunk)
                    on_chunk(chunk)
                returncode = process.wait()
                diagnostics.seek(0)
                detail = diagnostics.read(65536).decode("utf-8", errors="replace").strip()
                if returncode:
                    raise AdbError(detail or f"ADB 傳輸失敗（結束碼 {returncode}）。")
                if copied != expected_size:
                    raise AdbError(
                        f"傳輸不完整：預期 {expected_size} bytes，收到 {copied} bytes。"
                        + (f" {detail}" if detail else "")
                    )
                return copied
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close()
