"""Produce deterministic raw binary stdout and stderr for subprocess pipe tests."""

import sys


if __name__ == "__main__":
    if sys.argv[1] == "error":
        sys.stderr.buffer.write(b"fixture error\n")
        raise SystemExit(1)
    sys.stderr.buffer.write(b"diagnostic\n" * 200000)
    sys.stderr.buffer.flush()
    sys.stdout.buffer.write(bytes(range(256)) * 8192)
