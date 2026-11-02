"""Publish a local file only after validating its complete root ADB transfer."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Callable

from .adb import AdbClient, AdbError


@dataclass(frozen=True)
class PullResult:
    """Describe a verified local file, its byte count, and its SHA-256 digest."""

    destination: Path
    size: int
    sha256: str


def _publish(temporary: Path, destination: Path, overwrite: bool) -> None:
    if overwrite:
        os.replace(temporary, destination)
    elif os.name == "nt":
        # Windows rename refuses an existing target, including one created while
        # the transfer was running. POSIX rename would silently overwrite it.
        os.rename(temporary, destination)
    else:
        os.link(temporary, destination)
        temporary.unlink()


def pull_file(
    client: AdbClient,
    remote: str,
    local: str | Path | None = None,
    *,
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
    stage: Callable[[str], None] | None = None,
) -> PullResult:
    """Pull an absolute remote file to local with hash checks and optional callbacks.

    An existing local directory receives the source basename. By default existing
    files are preserved. Return the verified destination, size, and SHA-256.
    """
    destination = Path(local).expanduser() if local is not None else Path.cwd()
    if destination.is_dir():
        destination /= PurePosixPath(remote).name
    destination = destination.absolute()
    if os.path.lexists(destination) and not overwrite:
        raise FileExistsError(f"目的檔案已存在：{destination}；可用 --overwrite 允許覆寫。")
    if stage:
        stage("讀取來源資訊與 SHA-256（大檔案需要較長時間）…")
    before = client.inspect_file(remote)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(destination.parent).free < before.info.size:
        raise AdbError(f"本機可用空間不足；需要至少 {before.info.size} bytes。")

    digest = hashlib.sha256()
    copied = 0

    def consume(chunk: bytes) -> None:
        nonlocal copied
        digest.update(chunk)
        copied += len(chunk)
        if progress:
            progress(copied, before.info.size)

    descriptor, name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".part"
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            if stage:
                stage("直接從手機串流傳輸…")
            received = client.stream_file(remote, output, before.info.size, consume)
            if received != before.info.size or copied != before.info.size:
                raise AdbError("傳輸大小與來源不符。")
            if digest.hexdigest() != before.sha256:
                raise AdbError("SHA-256 不一致：傳輸內容損毀或來源已變動。")
            output.flush()
            os.fsync(output.fileno())

        if stage:
            stage("重新檢查來源 SHA-256 與檔案資訊…")
        after = client.inspect_file(remote)
        if after != before:
            raise AdbError("傳輸期間來源檔案已變動；請停止寫入該檔案後重試。")
        _publish(temporary, destination, overwrite)
        return PullResult(destination, copied, digest.hexdigest())
    finally:
        temporary.unlink(missing_ok=True)
