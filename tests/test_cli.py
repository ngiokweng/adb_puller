"""Check CLI summaries, transfer options and error exit codes."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from adb_puller.adb import AdbError
from adb_puller.cli import main
from adb_puller.transfer import DirectoryPullResult, PullResult


class CliTests(unittest.TestCase):
    """Exercise command parsing and output for both transfer result types."""

    def test_file_and_directory_summaries(self) -> None:
        """Show a folder count or a file digest and forward transfer settings."""
        for result, expected in (
            (DirectoryPullResult(Path("backup"), 123, 2), "檔案數：2"),
            (PullResult(Path("backup.bin"), 123, "a" * 64), "SHA-256：" + "a" * 64),
        ):
            with self.subTest(result=result):
                output = io.StringIO()
                with patch("adb_puller.cli.AdbClient") as client:
                    with patch("adb_puller.cli.pull", return_value=result) as transfer:
                        with redirect_stdout(output), redirect_stderr(io.StringIO()):
                            code = main(["-s", "serial", "pull", "/private/source", "backup",
                                         "--overwrite", "--jobs", "2", "--compression", "gzip"])
                self.assertEqual(code, 0)
                self.assertIn(expected, output.getvalue())
                client.assert_called_once_with("adb", "serial", jobs=2, compression="gzip")
                self.assertEqual(transfer.call_args.args, (client.return_value, "/private/source", "backup"))
                self.assertTrue(transfer.call_args.kwargs["overwrite"])

    def test_failure_and_cancellation(self) -> None:
        """Translate transfer failures and interruption into documented exit codes."""
        for failure, expected in ((AdbError("test failure"), 1), (KeyboardInterrupt(), 130)):
            with self.subTest(failure=failure):
                with patch("adb_puller.cli.pull", side_effect=failure):
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(main(["pull", "/private/source"]), expected)
