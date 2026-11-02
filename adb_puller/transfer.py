"""Pull root-protected files and directories with verified file publication."""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import shutil
import tempfile
import tarfile
from typing import BinaryIO, Callable
import zlib

from .adb import AdbClient, AdbError, DirectoryEntry


@dataclass(frozen=True)
class PullResult:
    """Describe a verified local file, its byte count, and its SHA-256 digest."""

    destination: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class DirectoryPullResult:
    """Describe a verified directory archive's destination, bytes and file count."""

    destination: Path
    size: int
    file_count: int


def _local_relative(path: str) -> Path:
    parts = tuple(path.split("/"))
    relative = Path(*parts)
    if (
        any(part in ("", ".", "..") for part in parts)
        or relative.is_absolute() or relative.parts != parts
        or (os.name == "nt" and any(
            PureWindowsPath(part).is_reserved() or part.endswith((" ", "."))
            or any(char in '<>:"|?*' or ord(char) < 32 for char in part)
            for part in parts
        ))
    ):
        raise AdbError(f"來源檔名無法安全儲存於本機：{path!r}")
    return relative


def _destination(remote: str, local: str | Path | None) -> Path:
    destination = Path(local).expanduser() if local is not None else Path.cwd()
    if destination.is_dir():
        name = PurePosixPath(posixpath.normpath(remote)).name
        if not name:
            raise AdbError("拉取手機根目錄時，請指定尚不存在的本機目的路徑。")
        destination /= _local_relative(name)
    return destination.absolute()


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
    files are preserved. Initial source hashing overlaps copying; publication
    waits for all integrity checks. Return the destination, size, and SHA-256.
    """
    destination = _destination(remote, local)
    if os.path.lexists(destination) and not overwrite:
        raise FileExistsError(f"目的檔案已存在：{destination}；可用 --overwrite 允許覆寫。")
    if stage:
        stage("讀取來源資訊…")
    with client.inspect_file_later(remote) as inspection:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(destination.parent).free < inspection.info.size:
            raise AdbError(f"本機可用空間不足；需要至少 {inspection.info.size} bytes。")

        copied = 0

        def consume(chunk: bytes) -> None:
            nonlocal copied
            # Surface hash failures during copying instead of transferring a
            # large file all the way before discovering a missing hash command.
            if inspection.done():
                inspection.result()
            copied += len(chunk)
            if progress:
                progress(copied, inspection.info.size)

        descriptor, name = tempfile.mkstemp(
            dir=destination.parent, prefix=f".{destination.name}.", suffix=".part"
        )
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w+b") as output:
                if stage:
                    stage("直接從手機串流傳輸（同步計算來源 SHA-256）…")
                received = client.stream_file(remote, output, inspection.info.size, consume)
                if received != inspection.info.size or copied != inspection.info.size:
                    raise AdbError("傳輸大小與來源不符。")
                if stage:
                    stage("驗證本機 SHA-256 並同步磁碟…")
                # Parallel ranges arrive out of order. Read the assembled file
                # in order while the initial remote hash may still be running.
                output.seek(0)
                digest = hashlib.sha256()
                while chunk := output.read(4 * 1024 * 1024):
                    digest.update(chunk)
                if stage:
                    stage("核對來源 SHA-256…")
                before = inspection.result()
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


def pull_directory(
    client: AdbClient,
    remote: str,
    local: str | Path | None = None,
    *,
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
    stage: Callable[[str], None] | None = None,
) -> DirectoryPullResult:
    """Pull one tar/gzip stream, verify its SHA-256, then publish its contents.

    An existing local directory receives the source basename. With overwrite,
    merge into that destination, preserving unrelated files. progress receives
    wire bytes and total=0 (unknown); stage receives phase descriptions. Failure
    before publication removes the staged tree and preserves existing files.
    Return the destination, total extracted bytes and file count.
    """
    destination = _destination(remote, local)
    if os.path.lexists(destination) and not overwrite:
        raise FileExistsError(f"目的目錄已存在：{destination}；可用 --overwrite 允許合併覆寫。")
    if stage:
        stage("讀取來源目錄清單…")
    entries = client.list_directory(remote)
    targets = [(destination, True)]
    seen: set[str] = set()
    for entry in entries:
        relative = _local_relative(entry.path)
        key = os.path.normcase(str(relative))
        if key in seen:
            raise AdbError(f"來源檔名在本機互相衝突：{entry.path!r}")
        seen.add(key)
        targets.append((destination / relative, entry.is_dir))

    _check_directory_targets(targets, overwrite)
    destination.parent.mkdir(parents=True, exist_ok=True)
    copied = 0

    def consume(chunk: bytes) -> None:
        nonlocal copied
        copied += len(chunk)
        if progress:
            progress(copied, 0)

    with tempfile.TemporaryDirectory(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".part",
    ) as temporary:
        staging = Path(temporary)
        if stage:
            stage("整個目錄打包並串流傳輸（手機同步壓縮／計算整批 SHA-256）…")
        with client.stream_directory(remote, consume) as source:
            size, count = _extract_directory(source, staging, entries)
            if stage:
                stage("核對整批 SHA-256…")
        # Local paths may have changed while the archive was being downloaded.
        _check_directory_targets(targets, overwrite)
        if stage:
            stage("整批驗證成功，發布資料夾…")
        if not destination.exists():
            os.rename(staging, destination)
        else:
            for target, is_dir in targets:
                if is_dir:
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    relative = target.relative_to(destination)
                    _publish(staging / relative, target, overwrite)
    return DirectoryPullResult(destination, size, count)


def _check_directory_targets(targets: list[tuple[Path, bool]], overwrite: bool) -> None:
    if not overwrite and os.path.lexists(targets[0][0]):
        raise FileExistsError(f"目的目錄已存在：{targets[0][0]}；可用 --overwrite 允許合併覆寫。")
    for target, is_dir in targets:
        if target.is_symlink() or getattr(target, "is_junction", lambda: False)():
            raise AdbError(f"目的路徑是符號連結或目錄連接點：{target}")
        if os.path.lexists(target):
            if is_dir and not target.is_dir():
                raise NotADirectoryError(f"目的路徑不是目錄：{target}")
            if not is_dir and not target.is_file():
                raise IsADirectoryError(f"目的路徑不是一般檔案：{target}")
            if not is_dir and not overwrite:
                raise FileExistsError(f"目的檔案已存在：{target}")


def _archive_path(name: str) -> str:
    if name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def _extract_directory(
    source: BinaryIO, staging: Path, entries: list[DirectoryEntry],
) -> tuple[int, int]:
    expected = {entry.path: entry.is_dir for entry in entries}
    extracted: set[str] = set()
    size = count = 0
    buffered = io.BufferedReader(source)
    archive = None
    try:
        # GzipFile limits decompression output to each read's requested size.
        # tarfile's built-in streaming gzip decoder can expand a small input
        # block into a large allocation for highly compressible logs.
        archive = gzip.GzipFile(fileobj=buffered) if buffered.peek(2)[:2] == b"\x1f\x8b" else buffered
        with tarfile.open(fileobj=archive, mode="r|", encoding="utf-8", errors="strict") as tar:
            for member in tar:
                name = _archive_path(member.name)
                if name in ("", ".") and member.isdir():
                    continue
                relative = _local_relative(name)
                if name not in expected or name in extracted or expected[name] != member.isdir():
                    raise AdbError(f"打包內容與來源目錄清單不一致：{name!r}")
                target = staging / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isreg():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    content = tar.extractfile(member)
                    if content is None:
                        raise AdbError(f"無法讀取打包檔案：{name!r}")
                    with content, target.open("xb") as output:
                        shutil.copyfileobj(content, output, length=4 * 1024 * 1024)
                    if target.stat().st_size != member.size:
                        raise AdbError(f"打包檔案大小不符：{name!r}")
                    size += member.size
                    count += 1
                elif member.islnk():
                    link_name = _archive_path(member.linkname)
                    link = staging / _local_relative(link_name)
                    if link_name not in extracted or expected.get(link_name) is not False:
                        raise AdbError(f"打包硬連結指向無效檔案：{name!r}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(link, target)
                    size += target.stat().st_size
                    count += 1
                else:
                    raise AdbError(f"打包內容包含符號連結或特殊檔案：{name!r}")
                extracted.add(name)
        if extracted != expected.keys():
            raise AdbError("打包內容缺少檔案或目錄；來源可能已變動。")
        # Read gzip's trailer too, checking CRC/length and the outer SHA-256
        # frame even when tar stopped at its end-of-archive padding.
        while archive.read(4 * 1024 * 1024):
            pass
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, UnicodeError, zlib.error) as error:
        raise AdbError(f"目錄打包串流損毀或不完整：{error}") from error
    finally:
        if archive is not None and archive is not buffered:
            archive.close()
        buffered.detach()
    return size, count


def pull(
    client: AdbClient,
    remote: str,
    local: str | Path | None = None,
    *,
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
    stage: Callable[[str], None] | None = None,
) -> PullResult | DirectoryPullResult:
    """Detect the remote type and return a verified file or directory result.

    Pass local destination, overwrite policy and optional transfer progress and
    stage callbacks to the matching transfer function.
    """
    transfer = pull_directory if client.path_kind(remote) == "directory" else pull_file
    return transfer(client, remote, local, overwrite=overwrite, progress=progress, stage=stage)
