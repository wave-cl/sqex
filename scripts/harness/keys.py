#!/usr/bin/env python3
"""Drive sqex-chat through a scripted sequence of keys and print the screen.

    python3 keys.py script.txt /path/to/sqex-chat -i ~/.sqnr/identity-2

The script is a text file, one step per line:

    wait 7 | alice reads
    key ESC | a message is picked
    key a | the reaction picker
    type on our way | ENTER the reply landed

Steps are `wait <secs>`, `key <NAME-or-char>`, `type <text>`. Anything after a
`|` is a caption, and a step with one prints the screen after it settles; a
caption beginning ENTER also presses Return. Key names: ESC, ENTER, TAB, UP,
DOWN, CTRLC.

Two things worth knowing before writing a script. Escape is modal in this
client — it enters the message picker, and pressing it again leaves — so an odd
number of them lands you somewhere you did not mean, and the next bare letter
goes into the message line instead of acting on a message. And `type` settles
for only a moment, so put an explicit `wait` after anything that has to reach
the exchange and come back.

The emulator lives in tui.py.
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

ROWS, COLS = 40, 120

NAMES = {
    "ESC": "\x1b",
    "ENTER": "\r",
    "TAB": "\t",
    "UP": "\x1b[A",
    "DOWN": "\x1b[B",
    "CTRLC": "\x03",
}


def parse(path):
    steps = []
    for line in open(path):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        body, _, caption = line.partition("|")
        body, caption = body.strip(), caption.strip()
        verb, _, rest = body.partition(" ")
        rest = rest.strip()
        if verb == "wait":
            steps.append(("", float(rest or 1), caption))
        elif verb == "key":
            steps.append((NAMES.get(rest, rest), 1.5, caption))
        elif verb == "type":
            keys = rest
            if caption.startswith("ENTER"):
                keys += "\r"
                caption = caption[5:].strip()
            steps.append((keys, 0.6, caption))
        else:
            raise SystemExit(f"unknown step: {line!r}")
    return steps


def main():
    steps = parse(sys.argv[1])
    args = sys.argv[2:]
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

    # Whatever happens in here, the client gets shut down: a harness that
    # leaves the thing it was driving still running is worse than none.
    try:
        for keys, secs, caption in steps:
            if keys:
                os.write(fd, keys.encode())
            pump(secs)
            if caption:
                print(f"\n{'=' * 72}\n{caption}\n{'=' * 72}")
                print(scr.render())
    finally:
        tui.shutdown(pid, fd)


main()
