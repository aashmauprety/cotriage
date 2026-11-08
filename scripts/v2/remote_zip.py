"""Read members of a remote zip (Zenodo) with HTTP range requests, without downloading the whole archive.

Usage:
  python -I scripts/v2/remote_zip.py list <scenario>                 -> member names and sizes
  python -I scripts/v2/remote_zip.py get <scenario> <out_dir> <regex> -> extract matching members
"""
import re
import shutil
import sys
import urllib.request
import time
import zipfile

URL = "https://zenodo.org/records/5789064/files/{}.zip?download=1"


class RangeFile:
    """Seekable read-only file over HTTP range requests, with a small read-ahead buffer."""

    def __init__(self, url):
        self.url, self.pos = url, 0
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as r:
            self.size = int(r.headers["Content-Length"])
        self.buf_start, self.buf = 0, b""

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.size + off
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        end = min(self.pos + n, self.size)
        if not (self.buf_start <= self.pos and end <= self.buf_start + len(self.buf)):
            fetch_end = min(max(end, self.pos + (1 << 20)), self.size)  # read ahead >= 1 MB
            req = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{fetch_end - 1}"})
            for attempt in range(8):  # Zenodo connections drop now and then
                try:
                    with urllib.request.urlopen(req, timeout=120) as r:
                        self.buf = r.read()
                    break
                except Exception:
                    if attempt == 7:
                        raise
                    time.sleep(5 * (attempt + 1))
            self.buf_start = self.pos
        out = self.buf[self.pos - self.buf_start:end - self.buf_start]
        self.pos += len(out)
        return out


def main():
    cmd, scen = sys.argv[1], sys.argv[2]
    zf = zipfile.ZipFile(RangeFile(URL.format(scen)))
    if cmd == "list":
        for i in zf.infolist():
            print(f"{i.file_size:>14d} {i.compress_size:>14d}  {i.filename}")
    elif cmd == "get":
        out, pat = sys.argv[3], re.compile(sys.argv[4])
        for i in zf.infolist():
            if pat.search(i.filename) and not i.is_dir():
                import os
                dst = f"{out}/{i.filename}"
                if os.path.exists(dst) and os.path.getsize(dst) == i.file_size:
                    continue  # already fetched
                print(f"extract {i.filename} ({i.compress_size / 1e6:.1f} MB compressed)", flush=True)
                dst = f"{out}/{i.filename}"
                import os
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with zf.open(i) as src, open(dst, "wb") as f:
                    shutil.copyfileobj(src, f, 1 << 20)


if __name__ == "__main__":
    main()
