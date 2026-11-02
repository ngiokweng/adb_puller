"""Produce deterministic raw binary stdout and stderr for subprocess pipe tests."""

import gzip
import sys
import time


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode in ("hash", "hash_bad", "hash_unframed"):
        digest = "A" * 64 if mode != "hash_bad" else "invalid digest"
        sys.stdout.write(digest + "\n")
        if mode != "hash_unframed":
            sys.stdout.write("ADB_PULLER_OK\n")
        raise SystemExit(0)
    if mode == "error":
        sys.stderr.buffer.write(b"fixture error\n")
        raise SystemExit(1)
    if mode == "hang":
        sys.stdout.buffer.write(bytes(4 * 1024**2))
        sys.stdout.buffer.flush()
        time.sleep(60)
        raise SystemExit(0)
    if mode in ("range", "gzip_range"):
        start, length = map(int, sys.argv[2:4])
        if start == 0:
            time.sleep(0.2)
        data = b"".join(
            bytes([(start + offset) // 1024**2 % 256]) * min(1024**2, length - offset)
            for offset in range(0, length, 1024**2)
        )
        sys.stdout.buffer.write(gzip.compress(data) if mode == "gzip_range" else data)
        raise SystemExit(0)
    if mode.startswith("gzip"):
        data = b"" if mode == "gzip_empty" else bytes(range(256)) * 8192
        payload = gzip.compress(data)
        if mode == "gzip_short":
            payload = payload[:-1]
        elif mode == "gzip_corrupt":
            payload = payload[:-8] + bytes([payload[-8] ^ 1]) + payload[-7:]
        elif mode == "gzip_trailing":
            payload += b"unexpected"
        sys.stdout.buffer.write(payload)
        raise SystemExit(0)
    sys.stderr.buffer.write(b"diagnostic\n" * 200000)
    sys.stderr.buffer.flush()
    sys.stdout.buffer.write(bytes(range(256)) * 8192)
