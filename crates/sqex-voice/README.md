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

**One identity, one client.** A session is named by two identities, so two
processes running as the same identity look identical to the exchange and will
keep discarding each other's session. Neither connects, and whoever they are
both calling waits forever. If a call sits at "waiting" for more than a few
seconds, check for a stray earlier process before anything else:

```bash
pgrep -fl sqex-voice
```

### Devices and rates

```bash
sqex-voice --list-devices
```

```
Inputs:
  ACCENTUM Plus  (default)
    offers: 16000
    would run at: 16 kHz
  MacBook Pro Microphone
    offers: 44100, 48000, 88200, 96000
    would run at: 48 kHz
Outputs:
  ACCENTUM Plus  (default)
    offers: 16000, 44100
    would run at: 44100 device, resampled to 48 kHz
```

`--in <name>` and `--out <name>` pick devices by any part of the name; without
them the system defaults are used.

There is nothing to negotiate about rates. Opus encodes at 8, 12, 16, 24 or
48 kHz and decodes any stream at whatever rate the listener wants, so each end
just runs at its own device's rate and the codec reconciles them. A 16 kHz
caller and a 48 kHz listener is a perfectly ordinary call. Only a device that
offers none of those rates — usually a 44.1 kHz output — needs the resampler,
and that happens at the device edge.

**The Bluetooth trap.** On macOS, capturing from a Bluetooth headset switches it
into HFP, which drops **both** directions to 16 kHz mono and sounds noticeably
worse. It works, and `sqex-voice` says so when it happens. To avoid it, capture
from the built-in microphone and play to the headset, which keeps the headset in
A2DP:

```bash
sqex-voice call <peer> --in "MacBook Pro Microphone" --out ACCENTUM
```

### Without a microphone

Every part of the call works without audio hardware, which is how it is tested:

```bash
sqex-voice call <peer> --source tone --sink /tmp/heard.wav --seconds 10
```

- `--source mic | tone | <file.wav>` — `tone` is a 440 Hz sine; a file must be
  48 kHz, since a file has no device whose rate to follow.
- `--sink speaker | null | <file.wav>`.

### More than two: rooms (SIP-13)

```bash
sqex-voice room --new          # mint a room secret
sqex-voice room <secret>       # everyone runs this
```

A room is named by a secret, and holding the secret is what being in the room
consists of. There is no owner, no invite list and no way to remove anyone:
**whoever you give it to can join, and can pass it on.** To exclude someone,
mint a new room and move.

What the secret *does* buy is that nobody else can get in, including whoever
runs the exchange. The exchange is given `SHA-256(context || secret)` and never
the secret, so it cannot join a room it is relaying. Each member also carries a
MAC under the secret, which the exchange can relay but neither check nor forge —
so if it adds an identity of its own to the roster, every member rejects it:

```
! 7Fk2Qm4x is listed in the room but cannot prove they hold the secret — ignoring them
```

That line, and the roster, are the only control a member has. They are printed
for that reason.

Media is a **mesh**: every pair runs an ordinary SIP-12 session, so a room adds
no cryptography and the exchange can read no more of a room than it can of a
call. The cost is that it grows as the square — eight people, the maximum, is
about 168 kbit/s of uplink each — which is why the maximum is eight.

```
2 here · *3yMhjNhZ loss 0% conceal 0 buf 3 | *GkpAfVhY loss 0% conceal 0 buf 3
```

A `*` marks someone speaking. Each peer has its own jitter buffer and its own
delay, so one bad path does not add latency for everybody else.

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

## Silence is free-ish (SIP-14)

A speaker who is not talking stops transmitting. Measured on a live exchange,
two seconds of speech followed by ten of silence:

| | packets |
|---|---|
| `--no-dtx` (continuous) | 600 |
| default | **157** |

In a room that saving applies to every one of the N(N−1) streams, which is what
makes eight people affordable.

Getting this right needs more than "stop sending". A receiver seeing missing
packets cannot tell a pause from loss, and a jitter buffer that guesses wrong
asks the codec to conceal — which extrapolates from the last thing it heard, and
so invents speech out of a silence nobody spoke. SIP-14 carries a media
timestamp beside the packet sequence, so the two are distinguishable: a
timestamp gap with no sequence gap is a pause, a sequence gap is loss. The
`silent` and `concealed` counters on the stats line report which is happening.

Two things Opus does that are worth knowing, both measured rather than
documented: DTX takes about **ten frames to engage**, so short pauses save less
than long ones; and it **refreshes its comfort noise** every few hundred
milliseconds, so a settled pause is not literally one keepalive per second.

`--no-dtx` restores continuous transmission. That is a **privacy** switch, not a
quality one: with DTX, packet timing tells anyone watching — the exchange
included — exactly when each person speaks. The content stays sealed; the
pattern of the conversation does not.

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
- **silent** is a slot the speaker deliberately left empty (SIP-14). Never
  concealed — that is the whole point of carrying a timestamp.
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
- `src/room.rs` — SIP-13: the roster, proof checking, and a session per peer.
- `src/media.rs` — SIP-14: the timestamp that tells a pause from a lost packet.
- `src/mix.rs` — adding several people together without pumping.
- `src/main.rs` — the rendezvous and the call loops.
- `tests/voice_flow.rs` — a tone through a real `sqexd`, out the far side still
  a tone; and the same with frames deliberately dropped.
- `tests/room_flow.rs` — three people, three notes, each hearing the other two
  and not themselves.
