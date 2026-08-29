#!/usr/bin/env python3
"""Does the emulator give the same screen however the bytes arrive?

    python3 scripts/harness/selftest.py

A pty hands back whatever bytes are ready, so where the reads fall is not
something the client chooses or the harness controls. The screen must not
depend on it. That is one property, and it covers both ways this has gone
wrong: an escape sequence cut in half, and a multi-byte character cut in half.

It checks a second property too: that printing a screen prints **all** of it.

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


def check_whole_screen() -> bool:
    """Nothing that prints a screen may quietly drop any of it.

    The second property this file guards, and the one that has cost more time.
    `sqex-chat` bottom-aligns its transcript, so a short conversation is a
    header at the top, a long band of blank rows, and a few lines of messages
    just above the composer. Cut the top twenty lines out of that and you have
    a header and a rule — indistinguishable from a conversation that failed to
    load, and twice reported as one.

    The fixture below is that shape deliberately, and it is that shape because
    the first version of this check was not: it used an eight-row screen with
    content on the last line, against which "truncate to twenty rows" and
    "drop trailing blanks" are both no-ops. Both sabotages passed. A fixture
    has to be able to exhibit the fault before a test of it means anything.
    """
    ok = True
    tall = 30
    scr = tui.Screen(tall, COLS)
    reader = tui.Reader()
    # Header at the top, messages near the bottom above a composer on the last
    # row, and nothing in between — the real shape.
    reader.feed(
        scr,
        (
            "\x1b[2J\x1b[H"
            "\x1b[1;1H\u25c9 Carl Sanchez  connected"
            "\x1b[3;1H\u2580\u2580  Todd"
            "\x1b[26;1H\u2580\u2580 Todd"
            "\x1b[27;1H  lol  19:26"
            f"\x1b[{tall};1H ^C quit \u00b7 Tab"
        ).encode(),
    )

    lines = scr.render().split("\n")
    if len(lines) != tall:
        print(f"FAIL  render() gave {len(lines)} lines, the screen has {tall}")
        ok = False
    elif "lol" not in lines[26]:
        print("FAIL  render() lost a row, so the rows below it moved up")
        ok = False
    elif lines[10] != "":
        print("FAIL  render() put something in a blank row")
        ok = False
    else:
        print("ok    render() keeps every row, blank ones included")

    shown = scr.numbered("a short conversation")
    body = [l for l in shown.split("\n") if l[:3].strip().isdigit()]
    if len(body) != tall:
        print(f"FAIL  numbered() printed {len(body)} of {tall} rows")
        ok = False
    elif not any(l.startswith(" 27 ") and "lol" in l for l in body):
        print("FAIL  numbered() lost the messages, or numbered them wrongly")
        ok = False
    elif f"{tall} rows" not in shown:
        print("FAIL  numbered() does not state its own size, so a cut capture hides")
        ok = False
    else:
        print("ok    numbered() shows and numbers every row, and states the size")
    return ok


def main() -> int:
    ok = True
    for name, text in CASES.items():
        ok &= check(name, text.encode("utf-8"))
    print()
    ok &= check_whole_screen()
    print("\nall good" if ok else "\nthe harness is not showing what is on the screen")
    return 0 if ok else 1


sys.exit(main())
