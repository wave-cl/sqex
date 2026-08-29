#!/usr/bin/env python3
"""Open sqex-chat, look at the first conversation and the next one, and print
both screens as they actually look.

    python3 screen.py /path/to/sqex-chat -i ~/.sqnr/identity-2

Read-only: it presses Tab and then Ctrl-C, and types nothing.

The emulator lives in tui.py, which is worth reading before trusting a capture
— it is good enough to read content from and has limits that have twice made
correct output look broken.
"""

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

import tui

ROWS, COLS = 44, 130


def main():
    args = sys.argv[1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execvp(args[0], args)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    scr = tui.Screen(ROWS, COLS)
    reader = tui.Reader()

    def pump(sec):
        end = time.time() + sec
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if not r:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            reader.feed(scr, chunk)

    def shot(label):
        print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
        print(scr.render())

    # Whatever happens in here, the client gets shut down: a harness that
    # leaves the thing it was driving still running is worse than none.
    try:
        pump(8)
        shot("first conversation")
        os.write(fd, b"\t")
        pump(4)
        shot("next conversation")
    finally:
        tui.shutdown(pid, fd)


main()
