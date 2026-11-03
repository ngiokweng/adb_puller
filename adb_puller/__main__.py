"""Run the adb_puller command line interface with python -m adb_puller."""

# PyInstaller executes this file as a script without a parent package.
from adb_puller.cli import main

raise SystemExit(main())
