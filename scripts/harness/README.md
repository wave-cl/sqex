# Driving sqex-chat from a script

`sqex-chat` is a full-screen terminal program, so the only way to see what it
actually shows somebody is to give it a terminal and read the screen back.
These three files do that.

    python3 scripts/harness/screen.py sqex-chat -i ~/.sqnr/identity-2

opens the client, looks at the first conversation and the next one, and prints
both. It types nothing.

    python3 scripts/harness/keys.py script.txt sqex-chat -i ~/.sqnr/identity-2

drives a scripted sequence of keys. The script is one step per line:

    wait 8 | opened
    key TAB
    wait 3 | after Tab — confirm this is the right conversation
    type hello | ENTER
    wait 5 | sent

`wait <secs>`, `key <NAME-or-char>`, `type <text>`; anything after `|` is a
caption, and a step with one prints the screen. A caption beginning `ENTER`
also presses Return. Key names: `ESC ENTER TAB UP DOWN CTRLC`.

`tui.py` is the terminal emulator both use, and

    python3 scripts/harness/selftest.py

checks the one property it has to have: the screen must not depend on where the
reads fall. Run it after touching `tui.py`.

## What it is good for, and what it is not

It is good evidence about **content**: did the message arrive, does the name
show, did the command answer, is the conversation empty when it should not be.

It is weaker evidence about **geometry** — columns, padding, truncation — and
has twice made correct output look broken. The emulator handles what ratatui
emits and no more: no scroll region, no insert/delete, no alternate screen.

For anything about layout, use ratatui's own `TestBackend` and read
`buffer[(x, y)].symbol()` per cell. That is what the terminal is handed, and it
settles the question outright. Measure before reporting a layout bug.

## Three things that have caused real mistakes

**Half a character.** A pty hands back whatever bytes are ready, so a read can
land in the middle of a character. Decoding each read on its own made U+FFFD of
whatever straddled the boundary and lost the rest — and every non-ASCII
character this client draws is three bytes: the rule under the conversation
header, the identicon, the quotation arrow. A capture full of holes was
reported as a rendering fault in the client before this was understood.
`tui.Reader` holds the partial sequence now, and `selftest.py` is there so it
stays held.


**Escape is modal.** It enters the message picker and leaves it again, so an
odd number of them lands somewhere unintended and the next bare letter goes
into the message line instead of acting on a message — which is how a scripted
reply once went out as an ordinary message.

**The sidebar opens on the first conversation, not the one you want.** Capture
the screen and confirm the selection *before* typing. Sending a test message
into the wrong conversation leaves litter in a real one, and the confirmation
costs a `wait` step.

## Teardown

`tui.shutdown` is why the scripts end where they do, in a `finally`. A harness
that leaves the client running leaves it polling the exchange every 700 ms and
holding its store open; one such orphan was found still connected the following
morning. It escalates — Ctrl-C, then the hangup from closing the pty, then TERM
and KILL to the process group — and drains the pty while it waits, because a
client redrawing into a buffer nobody reads blocks in `write`, where it can
neither act on the interrupt nor exit.
