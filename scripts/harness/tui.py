#!/usr/bin/env python3
"""A terminal emulator good enough to read a ratatui screen from a pty.

Shared by screen.py and keys.py, which used to carry a copy each and drift.

Three things it has to get right, all of which the earlier copies got wrong,
and each of which produced output convincing enough to be believed:

1. **Wide characters.** An emoji occupies two columns. Advancing one column per
   character desynchronises everything after it on the line, which is how a
   correctly aligned reaction row came to look broken and got reported as a
   bug. Cells hold a whole grapheme cluster; a two-column cluster claims the
   next cell as a continuation, which renders as nothing.

2. **Escape sequences split across reads.** `os.read` returns whatever has
   arrived, which is regularly half of a sequence. The tail then failed to
   match and was printed as literal text — the `38;5;2;49m` and `15;34H`
   fragments in a capture. Anything that looks like the start of an incomplete
   sequence is now held back until the rest arrives.

3. **Erase.** ratatui redraws differentially, so a cell nobody rewrites keeps
   what it had. `ESC[0J`, `ESC[1J` and the three `ESC[K` forms all have to
   clear what they say they clear, or debris from an earlier frame stays on
   screen and looks like content.

It is still only good enough to *read*: no scroll region, no insert/delete, no
alternate screen. Those do not appear in what ratatui emits here.
"""

import os
import re
import select
import signal
import time
import unicodedata

# Anything that ends a CSI sequence.
CSI_FINAL = re.compile(r"[@-~]")

ZERO_WIDTH = ("️", "︎", "‍")


def cluster_width(cluster: str) -> int:
    """How many columns a grapheme cluster takes.

    Deliberately simple, and matching what a terminal does with what ratatui
    emits rather than implementing UAX #11 in full: East Asian Wide and
    Fullwidth are two, an emoji-presentation sequence is two, everything else
    is one.
    """
    base = cluster[0]
    if unicodedata.east_asian_width(base) in ("W", "F"):
        return 2
    if "️" in cluster:
        # An emoji-presentation selector turns a text symbol into an emoji,
        # which the terminal paints two columns wide. ❤️ is the one that
        # matters here, and the one that misleads: its base is neutral.
        return 2
    if unicodedata.category(base) in ("Mn", "Me", "Cf"):
        return 0
    return 1


def clusters(s: str):
    """Split into grapheme clusters, well enough for this purpose."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        i += 1
        cl = c
        while i < len(s):
            n = s[i]
            if unicodedata.combining(n) or n in ZERO_WIDTH:
                cl += n
                i += 1
                # A zero-width joiner binds the next base character in too,
                # which is what makes a family emoji one cluster.
                if n == "‍" and i < len(s):
                    cl += s[i]
                    i += 1
            else:
                break
        out.append(cl)
    return out


class Screen:
    def __init__(self, rows: int, cols: int):
        self.rows, self.cols = rows, cols
        self.blank()
        self.r = self.c = 0

    def blank(self):
        # None marks the second half of a wide cluster: it renders as nothing,
        # because the cluster before it already covers the column.
        self.grid = [[" "] * self.cols for _ in range(self.rows)]

    def _put_cell(self, r, c, v):
        if 0 <= r < self.rows and 0 <= c < self.cols:
            self.grid[r][c] = v

    def put(self, cl: str):
        w = cluster_width(cl)
        if w == 0:
            # A combining mark with nothing to combine with. Dropped rather
            # than given a cell of its own.
            return
        if self.c >= self.cols:
            self.c = self.cols - 1
        self._put_cell(self.r, self.c, cl)
        if w == 2:
            self._put_cell(self.r, self.c + 1, None)
        self.c += w

    def erase_line(self, mode: int):
        if not 0 <= self.r < self.rows:
            return
        rng = {
            0: range(self.c, self.cols),
            1: range(0, min(self.c + 1, self.cols)),
            2: range(0, self.cols),
        }.get(mode, range(self.c, self.cols))
        for x in rng:
            self.grid[self.r][x] = " "

    def erase_screen(self, mode: int):
        if mode == 2 or mode == 3:
            self.blank()
            return
        if mode == 0:
            self.erase_line(0)
            for y in range(self.r + 1, self.rows):
                self.grid[y] = [" "] * self.cols
        elif mode == 1:
            self.erase_line(1)
            for y in range(0, self.r):
                self.grid[y] = [" "] * self.cols

    def render(self) -> str:
        rows = []
        for row in self.grid:
            rows.append("".join(c for c in row if c is not None).rstrip())
        return "\n".join(rows)


def feed(scr: Screen, text: str) -> str:
    """Apply `text` to `scr`. Returns any incomplete tail to feed back later."""
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        if ch == "\x1b":
            # Hold back anything that might be the start of a sequence we have
            # not fully received. This is the whole of fix (2): without it the
            # remainder arrives next read with no ESC in front of it and is
            # printed as text.
            if i + 1 >= n:
                return text[i:]
            nxt = text[i + 1]
            if nxt == "[":
                m = CSI_FINAL.search(text, i + 2)
                if not m:
                    return text[i:]
                params = text[i + 2 : m.start()]
                final = text[m.start()]
                i = m.end()
                _csi(scr, params, final)
                continue
            if nxt == "]":
                end = text.find("\x07", i)
                if end == -1:
                    # OSC can also end with ST (ESC \), which we may not have.
                    st = text.find("\x1b\\", i)
                    if st == -1:
                        return text[i:]
                    i = st + 2
                    continue
                i = end + 1
                continue
            # A two-character escape: ESC =, ESC >, ESC ( B and so on.
            i += 2
            continue

        i += 1
        if ch == "\n":
            scr.r += 1
            scr.c = 0
        elif ch == "\r":
            scr.c = 0
        elif ch == "\b":
            scr.c = max(0, scr.c - 1)
        elif ch == "\t":
            scr.c = min((scr.c // 8 + 1) * 8, scr.cols - 1)
        elif ch >= " ":
            # Take the whole cluster, so a combining mark or variation
            # selector lands with the character it modifies.
            cl = clusters(text[i - 1 : i + 8])[0]
            i = i - 1 + len(cl)
            scr.put(cl)
    return ""


def _csi(scr: Screen, params: str, final: str):
    nums = [int(p) if p.isdigit() else 0 for p in params.split(";")] if params else []

    def n(k=0, default=1):
        return nums[k] if len(nums) > k and nums[k] else default

    if final == "H" or final == "f":
        scr.r = (nums[0] - 1) if len(nums) > 0 and nums[0] else 0
        scr.c = (nums[1] - 1) if len(nums) > 1 and nums[1] else 0
    elif final == "J":
        scr.erase_screen(nums[0] if nums else 0)
    elif final == "K":
        scr.erase_line(nums[0] if nums else 0)
    elif final == "A":
        scr.r -= n()
    elif final == "B":
        scr.r += n()
    elif final == "C":
        scr.c += n()
    elif final == "D":
        scr.c -= n()
    elif final == "G":
        scr.c = n() - 1
    elif final == "d":
        scr.r = n() - 1
    # m (colour), h/l (modes), and the rest change nothing we render.
    scr.r = max(0, min(scr.r, scr.rows - 1))
    scr.c = max(0, min(scr.c, scr.cols - 1))


# ---- tearing the child down ------------------------------------------------


def _wait_for(pred, secs: float, fd: int | None = None) -> bool:
    """Wait for `pred`, draining `fd` meanwhile.

    The draining matters. A pty has a finite buffer, and a client redrawing
    into one nobody is reading blocks in `write` — where it will not act on the
    Ctrl-C it was just sent, and cannot exit. Waiting without reading is
    therefore a way of causing the very hang being waited out.
    """
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        if fd is not None:
            try:
                r, _, _ = select.select([fd], [], [], 0.05)
                if r:
                    os.read(fd, 65536)
                    continue
            except OSError:
                pass
        time.sleep(0.05)
    return pred()


def _close(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def shutdown(pid: int, fd: int, grace: float = 4.0) -> None:
    """Make certain the child under the pty is gone before we exit.

    Sending Ctrl-C and hoping was not enough: a client that had not quit within
    the couple of seconds allowed was simply left behind, and one of them was
    found the next morning still polling the exchange every 700 ms and holding
    its store open. A harness that leaves the thing it was driving running is
    worse than no harness.

    Escalates: Ctrl-C, which the client handles cleanly and which lets it close
    its store; then the hangup that comes of closing the master; then TERM and
    KILL to the whole process group, since `pty.fork` makes the child a session
    leader and anything it spawned belongs to it.
    """

    def reaped() -> bool:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        except OSError:
            return True
        return done == pid

    try:
        os.write(fd, b"\x03")
    except OSError:
        pass
    if _wait_for(reaped, grace, fd):
        _close(fd)
        return

    _close(fd)
    if _wait_for(reaped, 1.0):
        return

    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, OSError):
                return
        if _wait_for(reaped, 2.0):
            return
