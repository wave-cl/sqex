#!/usr/bin/env python3
"""Does the emulator give the same screen however the bytes arrive?

    python3 scripts/harness/selftest.py

A pty hands back whatever bytes are ready, so where the reads fall is not
something the client chooses or the harness controls. The screen must not
depend on it. That is one property, and it covers both ways this has gone
wrong: an escape sequence cut in half, and a multi-byte character cut in half.

The second is why this file exists. Reading in chunks and decoding each chunk
on its own turns a split character into U+FFFD and loses what followed it —
which put a hole through a box-drawing rule and ate the space after an
identicon, in a capture that was then reported as a rendering fault in the
client.
"""

import sys

import tui

ROWS, COLS = 8, 40


def render(chunks) -> str:
    """Drive a screen with `chunks` of bytes, exactly as the scripts do."""
    scr = tui.Screen(ROWS, COLS)
    reader = tui.Reader()
    for chunk in chunks:
        reader.feed(scr, chunk)
    return scr.render()


def split_every(data: bytes, n: int):
    return [data[i : i + n] for i in range(0, len(data), n)]


def check(name: str, data: bytes) -> bool:
    whole = render([data])
    for size in (1, 2, 3, 5, 7, 13):
        piecemeal = render(split_every(data, size))
        if piecemeal != whole:
            print(f"FAIL  {name}: {size}-byte reads differ from one read")
            for a, b in zip(whole.split("\n"), piecemeal.split("\n")):
                if a != b:
                    print(f"        one read: {a.rstrip()!r}")
                    print(f"      {size}-byte:   {b.rstrip()!r}")
            return False
    print(f"ok    {name}")
    return True


CASES = {
    # The characters this client actually draws: the rule under the
    # conversation header, the identicon, and the arrow on a quotation.
    "a rule of box-drawing": "─" * 30 + "\r\n",
    "an identicon and a name": "▀▀ Colin Lyons (6xhq7AJ4)\r\n",
    "a quotation": "  ↳ Tim (9kSYePuJ): This is another mess…\r\n",
    "an emoji with a count": " 😂 1  🧡 2 \r\n",
    # And the same, wrapped in the colour and cursor moves ratatui emits, so a
    # split can land inside an escape sequence as well as inside a character.
    "colour around a rule": "\x1b[38;2;120;126;138m" + "─" * 20 + "\x1b[0m\r\n",
    "a cursor move between glyphs": "\x1b[2;3H▀▀\x1b[3;5H↳ you\x1b[0m\r\n",
    "erase then redraw": "\x1b[2J\x1b[H▀▀ bob\r\n─────\r\n",
}


def main() -> int:
    ok = True
    for name, text in CASES.items():
        ok &= check(name, text.encode("utf-8"))
    print("\nall good" if ok else "\nthe emulator depends on where the reads fall")
    return 0 if ok else 1


sys.exit(main())
