# sqex-voice

A two-party voice call over a [SIP-12](https://github.com/wave-cl/sips) relayed
session. Twenty milliseconds of Opus, twenty times a second, carried on QUIC
datagrams through a `sqexd` that can read none of it.

This is a **demo**. It is not built or packaged with `sqex` and `sqexd`, is not
in the release archives, and `install.sh` does not know about it.

## Why it exists

SIP-12 added datagram carriage because polling a relayed session costs about
100 ms a frame and a datagram costs about 0.5 ms. That is the entire argument
for the unreliable path, and it had only ever been made with a stopwatch. This
makes it with audio.

The exchange forwards packets and does not manage a call. SIP-12 says so
plainly, and lists what an application must bring instead: a jitter buffer, loss
concealment, echo cancellation, a codec, and rate control. Everything here
except echo cancellation is that list.

**There is no echo cancellation. On speakers this will howl. Wear headphones.**

## Building

```bash
cargo build --release -p sqex-voice
```

`opus` builds libopus from source, so **cmake** must be on PATH. On Linux, cpal
needs the ALSA headers (`libasound2-dev`); macOS uses CoreAudio and needs
nothing extra.

## Using it

Both ends need a software identity (`sqnr keygen`) and the same exchange. A
YubiKey cannot be used: it signs, but it cannot be a transport identity.

SIP-12 requires **strict mutual consent**, so each end names the other and the
session only forms once both have asked. On one machine:

```bash
sqex-voice call <their-identity>
```

and on the other:

```bash
sqex-voice call <your-identity>
```

`--server` / `SQEX_SERVER`, `--server-key` / `SQEX_SERVER_KEY` and `--identity`
work exactly as they do in `sqex`, including the `~/.sqnr/config` defaults.

### Without a microphone

Every part of the call works without audio hardware, which is how it is tested:

```bash
sqex-voice call <peer> --source tone --sink /tmp/heard.wav --seconds 10
```

- `--source mic | tone | <file.wav>` — `tone` is a 440 Hz sine; a file must be
  48 kHz (there is no resampler here).
- `--sink speaker | null | <file.wav>`.

### Measuring the round trip

One person, two terminals. The echo responder reflects each frame back under
the sequence number it arrived with, so the caller can match a return to a
departure:

```bash
sqex-voice echo <caller-identity>                                  # terminal 1
sqex-voice call <echo-identity> --source tone --sink null --rtt    # terminal 2
```

The stats line then carries `rtt p50` and `rtt p95`, counting both relay hops
in each direction. `--rtt` is meaningless against another `call`, whose sequence
numbers are its own.

## What the numbers mean

```
sent 412 · recv 410 · loss 0.5% · late 0 · dup 0 · concealed 2 · trimmed 0 · underruns 0 · buffered 3
```

- **loss** is judged from the span of sequence numbers received, not from a
  report the peer would have to send.
- **late** is a frame that arrived after its slot had already been played — the
  jitter buffer was too shallow for the path. Raise `--jitter`, at 20 ms of
  added delay per frame.
- **concealed** is a slot Opus invented because the packet never came.
- **trimmed** is a frame decoded but not played, to shed delay the buffer had
  accumulated. A fixed-depth buffer cannot drain a backlog on its own — frames
  arrive no faster than they are played — so a stall early in the call would
  otherwise be carried as latency for the rest of it.
- **underruns** is the buffer emptying and refilling, which is what silence
  looks like from in here.

Measured on loopback against `echo`: 250 frames each way over five seconds,
no loss, round trip **p50 1.6 ms, p95 2.3 ms** across both relay hops. The
received audio was still a 440.0 Hz tone at the amplitude it left with.

## Layout

- `src/jitter.rs` — the jitter buffer and the decision of when to conceal.
  Concealment itself is Opus's; knowing *when* to ask for it is not.
- `src/audio.rs` — devices, the tone generator, WAV in and out, and the 48 kHz
  requirement.
- `src/main.rs` — the rendezvous and the call loop.
- `tests/voice_flow.rs` — a tone through a real `sqexd`, out the far side still
  a tone; and the same with frames deliberately dropped.
