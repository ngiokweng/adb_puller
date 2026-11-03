"""Provide the Traditional Chinese adb_puller command line interface."""

from __future__ import annotations

import argparse
import sys
import time

from .adb import AdbClient, AdbError
from .transfer import DirectoryPullResult, pull


def _size(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.2f} {unit}"
        amount /= 1024
    raise AssertionError("unreachable")


class _Progress:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.last_update = 0.0
        self.active = False

    def stage(self, message: str) -> None:
        """Print a phase message and restart the transfer speed timer."""
        self.finish()
        print(message, file=sys.stderr, flush=True)
        self.started = time.monotonic()

    def update(self, copied: int, total: int) -> None:
        """Display byte counts, completion percentage, and average speed."""
        now = time.monotonic()
        if copied != total and now - self.last_update < 0.25:
            return
        self.last_update = now
        speed = copied / max(now - self.started, 0.001)
        amount = (f"{copied / total * 100:6.2f}%  {_size(copied)} / {_size(total)}"
                  if total else f"已傳輸 {_size(copied)}")
        print(
            f"\r{amount}  {_size(int(speed))}/s",
            end="",
            file=sys.stderr,
            flush=True,
        )
        self.active = True

    def finish(self) -> None:
        """Terminate an active progress line before subsequent messages."""
        if self.active:
            print(file=sys.stderr, flush=True)
            self.active = False


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and return 0 on success, 1 on failure, or 130 on cancel."""
    parser = argparse.ArgumentParser(
        prog="adb_puller",
        description="透過 su root 拉取 Android 私有檔案或資料夾；目錄整批打包傳輸並驗證 SHA-256。",
    )
    parser.add_argument("--adb", default="adb", help="adb 執行檔路徑（預設：PATH 中的 adb）")
    parser.add_argument("-s", "--serial", help="裝置序號；多台裝置時請指定")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("devices", help="列出 ADB 裝置")
    pull_parser = commands.add_parser("pull", help="拉取檔案或整個資料夾（保留手機來源）")
    pull_parser.add_argument("remote", help="手機上的檔案或資料夾絕對路徑")
    pull_parser.add_argument("local", nargs="?", help="本機目的路徑（已存在目錄下保留來源名稱；預設：目前目錄）")
    pull_parser.add_argument("--overwrite", action="store_true", help="驗證成功後覆寫；目錄則整批驗證後合併內容")
    pull_parser.add_argument(
        "--jobs", type=int, choices=range(1, 9), default=4, metavar="1-8",
        help="單檔同時傳輸的區段數（預設：4；目錄使用一條打包串流）",
    )
    pull_parser.add_argument(
        "--compression", choices=("auto", "gzip", "none"), default="auto",
        help="串流壓縮（預設：auto；單檔取樣決定，目錄有 gzip 即壓縮）",
    )
    args = parser.parse_args(argv)
    client = AdbClient(
        args.adb, args.serial,
        jobs=getattr(args, "jobs", 4), compression=getattr(args, "compression", "auto"),
    )
    progress = _Progress()
    try:
        if args.command == "devices":
            print(client.devices(), end="")
        else:
            result = pull(
                client,
                args.remote,
                args.local,
                overwrite=args.overwrite,
                progress=progress.update,
                stage=progress.stage,
            )
            if isinstance(result, DirectoryPullResult):
                print(f"完成：{result.destination}\n檔案數：{result.file_count}\n"
                      f"總大小：{result.size} bytes\n目錄打包串流已通過 SHA-256 驗證。")
            else:
                print(f"完成：{result.destination}\n大小：{result.size} bytes\nSHA-256：{result.sha256}")
        return 0
    except KeyboardInterrupt:
        progress.finish()
        print("已取消傳輸，暫存檔已清除。", file=sys.stderr)
        return 130
    except (AdbError, OSError) as error:
        progress.finish()
        print(f"錯誤：{error}", file=sys.stderr)
        return 1
