//! Where the sound comes from and where it goes.
//!
//! Everything here deals in one shape: a 20 ms mono frame of `f32`, at whatever
//! [`Rate`] the device turned out to run at. Keeping the devices, the tone
//! generator and the WAV files all speaking that shape means the call loop never
//! has to know which of them it is talking to.
//!
//! That interchangeability is the point. A microphone needs hardware, a
//! permission prompt and a person to speak into it; a tone needs none of those,
//! so the same call can be run end to end, checked byte for byte, and put in a
//! test.
//!
//! # Rates
//!
//! Opus accepts 8, 12, 16, 24 or 48 kHz and nothing else — but it accepts any of
//! them, and a decoder may decode a stream at whatever rate it likes regardless
//! of what the encoder used. So there is nothing to negotiate: each end simply
//! runs at its own device's rate, and the codec converts. Capture and playback
//! are chosen independently for the same reason.
//!
//! Only a device offering *none* of those rates needs [`resample`], and in
//! practice that means a 44.1 kHz output. The resampling happens inside the
//! device callback, so nothing downstream ever sees a rate other than the one it
//! was told about.
//!
//! Synthetic sources and sinks — the tone, the WAV reader, the WAV writer — have
//! no device to accommodate and stay at [`SAMPLE_RATE`].
//!
//! # A trap worth naming
//!
//! On macOS, capturing from a Bluetooth headset switches it into HFP, which
//! drops **both** directions to 16 kHz mono. It still works, and it sounds
//! markedly worse. Capturing from the built-in microphone while playing to the
//! headset keeps the headset in A2DP, which is why `--in` and `--out` exist.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{BufferSize, SampleFormat, StreamConfig, SupportedStreamConfigRange};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::jitter::{FRAME_MS, FRAME_SAMPLES, SAMPLE_RATE};

/// Frequency of the synthetic source, in Hz. Concert A: unmistakable by ear and
/// trivially checkable by counting zero crossings.
pub const TONE_HZ: f32 = 440.0;

/// The rates Opus encodes and decodes natively, best first.
pub const OPUS_RATES: [u32; 5] = [48_000, 24_000, 16_000, 12_000, 8_000];

/// A rate the codec will run at, and the 20 ms frame that goes with it.
///
/// Carried around rather than assumed, because capture and playback need not
/// agree with each other, and neither needs to agree with the far end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate(u32);

impl Rate {
    /// What anything without a device runs at.
    pub const DEFAULT: Rate = Rate(SAMPLE_RATE);

    /// Only rates Opus accepts can be constructed.
    pub fn new(hz: u32) -> Option<Rate> {
        OPUS_RATES.contains(&hz).then_some(Rate(hz))
    }

    pub fn hz(self) -> u32 {
        self.0
    }

    /// Samples in one 20 ms frame at this rate.
    pub fn frame(self) -> usize {
        (self.0 as usize * FRAME_MS as usize) / 1000
    }
}

impl std::fmt::Display for Rate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_multiple_of(1000) {
            write!(f, "{} kHz", self.0 / 1000)
        } else {
            write!(f, "{:.1} kHz", self.0 as f32 / 1000.0)
        }
    }
}

/// Linear interpolation between two rates.
///
/// Only used where a device offers no rate Opus speaks, which in practice means
/// a 44.1 kHz output. Linear interpolation is not a good resampler — it is a
/// gentle low-pass with some aliasing above it — but for speech at the edge of
/// the path it is inaudible against everything else going on, and it is fifteen
/// lines instead of a dependency.
pub fn resample(input: &[f32], from: u32, to: u32) -> Vec<f32> {
    if from == to || input.is_empty() {
        return input.to_vec();
    }
    let ratio = from as f64 / to as f64;
    let out_len = ((input.len() as f64) / ratio).round() as usize;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let at = i as f64 * ratio;
        let j = at.floor() as usize;
        let frac = (at - j as f64) as f32;
        let a = input[j.min(input.len() - 1)];
        let b = input[(j + 1).min(input.len() - 1)];
        out.push(a + (b - a) * frac);
    }
    out
}

#[derive(Debug, Clone)]
pub enum Source {
    Mic,
    Tone,
    Wav(PathBuf),
}

#[derive(Debug, Clone)]
pub enum Sink {
    Speaker,
    Null,
    Wav(PathBuf),
}

impl std::str::FromStr for Source {
    type Err = String;
    fn from_str(s: &str) -> Result<Source, String> {
        match s {
            "mic" => Ok(Source::Mic),
            "tone" => Ok(Source::Tone),
            other => Ok(Source::Wav(PathBuf::from(other))),
        }
    }
}

impl std::str::FromStr for Sink {
    type Err = String;
    fn from_str(s: &str) -> Result<Sink, String> {
        match s {
            "speaker" => Ok(Sink::Speaker),
            "null" => Ok(Sink::Null),
            other => Ok(Sink::Wav(PathBuf::from(other))),
        }
    }
}

/// Open a source, and report the rate the codec should encode at.
///
/// The receiver yields one 20 ms frame at that rate and closes when the source
/// runs out — a WAV file reaching its end, or the device going away.
pub fn open_source(
    source: &Source,
    seconds: Option<u64>,
    device: Option<&str>,
) -> Result<(UnboundedReceiver<Vec<f32>>, Rate), String> {
    match source {
        Source::Mic => microphone(device),
        // Nothing to accommodate: a tone and a file have no sound card.
        Source::Tone => Ok((synthetic(tone_frames(), seconds), Rate::DEFAULT)),
        Source::Wav(path) => Ok((synthetic(wav_frames(path)?, seconds), Rate::DEFAULT)),
    }
}

/// Open a sink, and report the rate the decoders should decode at.
///
/// Dropping it stops the device; [`Output::finish`] closes a WAV file properly,
/// which a drop cannot do.
pub fn open_sink(sink: &Sink, device: Option<&str>) -> Result<(Output, Rate), String> {
    match sink {
        Sink::Speaker => speaker(device),
        Sink::Null => Ok((Output(Written::Nowhere), Rate::DEFAULT)),
        Sink::Wav(path) => Ok((wav_writer(path)?, Rate::DEFAULT)),
    }
}

// ---- sources ----------------------------------------------------------------

/// A 440 Hz sine, continuous across frames so there is no click at the seam.
fn tone_frames() -> impl Iterator<Item = Vec<f32>> {
    sine(TONE_HZ)
}

/// A sine at `hz`, in 20 ms frames, with the phase carried across the seam.
fn sine(hz: f32) -> impl Iterator<Item = Vec<f32>> {
    let mut phase = 0.0f32;
    let step = std::f32::consts::TAU * hz / SAMPLE_RATE as f32;
    std::iter::from_fn(move || {
        let mut frame = Vec::with_capacity(FRAME_SAMPLES);
        for _ in 0..FRAME_SAMPLES {
            frame.push(phase.sin() * 0.5);
            phase = (phase + step) % std::f32::consts::TAU;
        }
        Some(frame)
    })
}

/// Read a WAV file into 20 ms mono frames, padding the last one with silence.
fn wav_frames(path: &Path) -> Result<impl Iterator<Item = Vec<f32>> + use<>, String> {
    let mut reader =
        hound::WavReader::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let spec = reader.spec();
    if spec.sample_rate != SAMPLE_RATE {
        return Err(format!(
            "{} is {} Hz; this demo carries no resampler, so it needs {SAMPLE_RATE} Hz",
            path.display(),
            spec.sample_rate
        ));
    }
    let channels = spec.channels as usize;
    let mono: Vec<f32> = match spec.sample_format {
        hound::SampleFormat::Float => reader
            .samples::<f32>()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("read {}: {e}", path.display()))?,
        hound::SampleFormat::Int => {
            let scale = 1.0 / (1i64 << (spec.bits_per_sample - 1)) as f32;
            reader
                .samples::<i32>()
                .map(|s| s.map(|v| v as f32 * scale))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("read {}: {e}", path.display()))?
        }
    };
    let mono: Vec<f32> = mono
        .chunks(channels)
        .map(|c| c.iter().sum::<f32>() / channels as f32)
        .collect();

    let mut at = 0usize;
    Ok(std::iter::from_fn(move || {
        if at >= mono.len() {
            return None;
        }
        let end = (at + FRAME_SAMPLES).min(mono.len());
        let mut frame = mono[at..end].to_vec();
        frame.resize(FRAME_SAMPLES, 0.0);
        at = end;
        Some(frame)
    }))
}

/// Drive an iterator of frames at the real 20 ms cadence, so a synthetic source
/// paces the call exactly as a microphone would.
fn synthetic(
    mut frames: impl Iterator<Item = Vec<f32>> + Send + 'static,
    seconds: Option<u64>,
) -> UnboundedReceiver<Vec<f32>> {
    let (tx, rx) = unbounded_channel();
    let limit = seconds.map(|s| (s * 1000) / FRAME_MS);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(FRAME_MS));
        let mut sent = 0u64;
        loop {
            tick.tick().await;
            if limit.is_some_and(|l| sent >= l) {
                return;
            }
            match frames.next() {
                Some(f) => {
                    if tx.send(f).is_err() {
                        return;
                    }
                    sent += 1;
                }
                None => return,
            }
        }
    });
    rx
}

fn microphone(want: Option<&str>) -> Result<(UnboundedReceiver<Vec<f32>>, Rate), String> {
    let (tx, rx) = unbounded_channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(String, Chosen), String>>();
    let want = want.map(str::to_string);

    // A cpal stream is not Send on every platform and stops the moment it is
    // dropped, so it lives on a thread of its own that does nothing but hold it.
    std::thread::spawn(move || {
        let report = ready_tx.clone();
        let run = move || -> Result<(), String> {
            let device = pick_device(want.as_deref(), true)?;
            let name = describe(&device);
            let chosen = choose(
                device
                    .supported_input_configs()
                    .map_err(|e| format!("{name}: {e}"))?,
                &name,
                "capture",
            )?;
            let channels = chosen.config.channels as usize;
            let frame = chosen.rate.frame();
            let (device_hz, rate_hz) = (chosen.device_hz, chosen.rate.hz());
            let mut pending: Vec<f32> = Vec::with_capacity(frame * 2);
            let stream = device
                .build_input_stream::<f32, _, _>(
                    chosen.config,
                    move |data, _| {
                        let mono: Vec<f32> = data
                            .chunks(channels)
                            .map(|g| g.iter().sum::<f32>() / channels as f32)
                            .collect();
                        // Only when the device speaks no rate Opus does.
                        pending.extend(if device_hz == rate_hz {
                            mono
                        } else {
                            resample(&mono, device_hz, rate_hz)
                        });
                        while pending.len() >= frame {
                            let f: Vec<f32> = pending.drain(..frame).collect();
                            if tx.send(f).is_err() {
                                return; // the call ended
                            }
                        }
                    },
                    |e| eprintln!("microphone: {e}"),
                    None,
                )
                .map_err(|e| format!("open microphone: {e}"))?;
            stream.play().map_err(|e| format!("start capture: {e}"))?;
            let _ = ready_tx.send(Ok((name, chosen)));
            loop {
                // Holding `stream` is the whole job.
                std::thread::park();
            }
        };
        if let Err(e) = run() {
            let _ = report.send(Err(e));
        }
    });

    match ready_rx.recv() {
        Ok(Ok((name, chosen))) => {
            eprintln!("capturing from {name} at {}{}", chosen.rate, resampled(&chosen));
            // The cause of a narrowband capture is not guessable from the
            // number, and the remedy is one flag away.
            if chosen.rate.hz() <= 16_000 {
                eprintln!(
                    "  (a Bluetooth mic forces the headset to narrowband; \
                     --in \"MacBook Pro Microphone\" or similar keeps it in high quality)"
                );
            }
            Ok((rx, chosen.rate))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("the audio thread died before opening the microphone".into()),
    }
}

fn resampled(chosen: &Chosen) -> String {
    if chosen.resampling() {
        format!(" (device runs at {}, resampled)", chosen.device_hz)
    } else {
        String::new()
    }
}

// ---- sinks ------------------------------------------------------------------

enum Written {
    /// Handed to the speaker, which drains it at the device's own pace.
    Ring(Arc<Mutex<VecDeque<f32>>>),
    Wav(Arc<Mutex<Option<hound::WavWriter<std::io::BufWriter<std::fs::File>>>>>),
    Nowhere,
}

/// Somewhere for decoded audio to go.
pub struct Output(Written);

impl Output {
    pub fn play(&self, samples: &[f32]) {
        match &self.0 {
            Written::Ring(ring) => {
                let mut r = ring.lock().expect("audio ring");
                // If the device has stopped draining, do not grow without
                // bound: a backlog is latency, and latency is the enemy here.
                if r.len() > FRAME_SAMPLES * 8 {
                    r.clear();
                }
                r.extend(samples.iter().copied());
            }
            Written::Wav(w) => {
                if let Some(writer) = w.lock().expect("wav writer").as_mut() {
                    for s in samples {
                        let v = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                        let _ = writer.write_sample(v);
                    }
                }
            }
            Written::Nowhere => {}
        }
    }

    /// Close a WAV file so its header records the right length. A dropped
    /// writer leaves a file that most players will not open.
    pub fn finish(&self) -> Result<(), String> {
        if let Written::Wav(w) = &self.0
            && let Some(writer) = w.lock().expect("wav writer").take()
        {
            writer.finalize().map_err(|e| format!("finish wav: {e}"))?;
        }
        Ok(())
    }
}

fn wav_writer(path: &Path) -> Result<Output, String> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: SAMPLE_RATE,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let writer = hound::WavWriter::create(path, spec)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    Ok(Output(Written::Wav(Arc::new(Mutex::new(Some(writer))))))
}

fn speaker(want: Option<&str>) -> Result<(Output, Rate), String> {
    let ring: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::new()));
    let for_device = Arc::clone(&ring);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(String, Chosen), String>>();
    let want = want.map(str::to_string);

    std::thread::spawn(move || {
        let report = ready_tx.clone();
        let run = move || -> Result<(), String> {
            let device = pick_device(want.as_deref(), false)?;
            let name = describe(&device);
            let chosen = choose(
                device
                    .supported_output_configs()
                    .map_err(|e| format!("{name}: {e}"))?,
                &name,
                "playback",
            )?;
            let channels = chosen.config.channels as usize;
            let (device_hz, rate_hz) = (chosen.device_hz, chosen.rate.hz());
            let stream = device
                .build_output_stream::<f32, _, _>(
                    chosen.config,
                    move |data, _| {
                        let frames = data.len() / channels;
                        let mut r = for_device.lock().expect("audio ring");
                        // Underrun is silence, not a stall: the far end is
                        // simply not talking yet.
                        let take = |r: &mut VecDeque<f32>, n: usize| -> Vec<f32> {
                            (0..n).map(|_| r.pop_front().unwrap_or(0.0)).collect()
                        };
                        let mono = if device_hz == rate_hz {
                            take(&mut r, frames)
                        } else {
                            // Pull the working-rate samples this many device
                            // frames are worth, then stretch them.
                            let want = (frames as f64 * rate_hz as f64 / device_hz as f64)
                                .ceil() as usize;
                            let src = take(&mut r, want);
                            let mut out = resample(&src, rate_hz, device_hz);
                            out.resize(frames, 0.0);
                            out
                        };
                        for (group, s) in data.chunks_mut(channels).zip(mono) {
                            group.fill(s);
                        }
                    },
                    |e| eprintln!("speaker: {e}"),
                    None,
                )
                .map_err(|e| speaker_error(&name, &e.to_string()))?;
            stream.play().map_err(|e| format!("start playback: {e}"))?;
            let _ = ready_tx.send(Ok((name, chosen)));
            loop {
                std::thread::park();
            }
        };
        if let Err(e) = run() {
            let _ = report.send(Err(e));
        }
    });

    match ready_rx.recv() {
        Ok(Ok((name, chosen))) => {
            eprintln!("playing to {name} at {}{}", chosen.rate, resampled(&chosen));
            Ok((Output(Written::Ring(ring)), chosen.rate))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("the audio thread died before opening the speaker".into()),
    }
}

// ---- device configuration ---------------------------------------------------

fn describe<D: DeviceTrait>(device: &D) -> String {
    device
        .description()
        .map(|d| d.name().to_string())
        .unwrap_or_else(|_| "unnamed device".to_string())
}

/// What a device will be driven at, and what the codec will run at.
///
/// The two differ only when the device offers no rate Opus speaks; then the
/// device runs at its own rate and [`resample`] bridges the gap.
#[derive(Debug, Clone, Copy)]
pub struct Chosen {
    pub config: StreamConfig,
    /// The rate the codec works at.
    pub rate: Rate,
    /// The device's own rate. Equal to `rate.hz()` unless resampling.
    pub device_hz: u32,
}

impl Chosen {
    pub fn resampling(&self) -> bool {
        self.device_hz != self.rate.hz()
    }
}

/// The best rate this range can give, capped at 48 kHz.
///
/// Nothing above 48 kHz buys anything — it is the most Opus will encode — so a
/// device offering 96 kHz is asked for 48, not indulged.
fn best_of(range: &SupportedStreamConfigRange) -> u32 {
    if range.min_sample_rate() <= SAMPLE_RATE && range.max_sample_rate() >= SAMPLE_RATE {
        SAMPLE_RATE
    } else if range.max_sample_rate() < SAMPLE_RATE {
        range.max_sample_rate()
    } else {
        range.min_sample_rate() // everything it offers is above 48 kHz
    }
}

/// Pick a configuration: the best rate the device can actually give, and the
/// fewest channels — a mono capture needs no downmix, and a mono playback
/// wastes nothing.
///
/// **Quality decides first, and whether Opus speaks the rate decides second.**
/// That order matters, and getting it backwards is a real mistake: a Bluetooth
/// headset offers both 44.1 kHz (A2DP) and 16 kHz (HFP), and preferring 16
/// because Opus speaks it natively would drag the headset into narrowband to
/// save a resampler. So take the best rate on offer, then resample only if it
/// is not one Opus speaks.
fn choose(
    configs: impl Iterator<Item = SupportedStreamConfigRange>,
    device: &str,
    what: &str,
) -> Result<Chosen, String> {
    let usable: Vec<SupportedStreamConfigRange> = configs
        .filter(|r| r.sample_format() == SampleFormat::F32)
        .collect();
    if usable.is_empty() {
        return Err(format!("{device} offers no f32 {what}"));
    }

    // Highest rate at or below 48 kHz; failing that, the lowest above it.
    let device_hz = usable
        .iter()
        .map(best_of)
        .filter(|hz| *hz <= SAMPLE_RATE)
        .max()
        .unwrap_or_else(|| usable.iter().map(best_of).min().expect("non-empty"));

    let channels = usable
        .iter()
        .filter(|r| r.min_sample_rate() <= device_hz && r.max_sample_rate() >= device_hz)
        .map(|r| r.channels())
        .min()
        .unwrap_or(1);

    Ok(Chosen {
        config: StreamConfig {
            channels,
            sample_rate: device_hz,
            buffer_size: BufferSize::Default,
        },
        // Run the codec at the device's rate when Opus speaks it, and otherwise
        // at 48 kHz with the difference resampled at the device edge.
        rate: Rate::new(device_hz).unwrap_or(Rate::DEFAULT),
        device_hz,
    })
}

/// Find a device by case-insensitive substring, or the system default.
///
/// Returns the devices it did find when a name matches nothing, because the
/// What to say when a speaker will not open.
///
/// One cause dominates and the bare error names none of it. A Bluetooth headset
/// is a single device offering both a microphone and a speaker; opening the
/// microphone switches it from A2DP to HFP, and the speaker's sample rate
/// changes underneath whoever is opening it. CoreAudio reports that as
/// "Sample rate update timed out", which reads as a broken speaker and is
/// really a profile switch caused by the *capture* device.
///
/// The remedy is therefore on the other side of the call from the error, which
/// is why saying so matters: nobody debugging a speaker failure looks at their
/// microphone.
fn speaker_error(name: &str, e: &str) -> String {
    let profile_switch = e.contains("Sample rate")
        || e.contains("timed out")
        || e.contains("nope")
        || e.contains("Device unavailable");
    if profile_switch {
        format!(
            "open speaker {name}: {e}\n  \
             This usually means the device changed profile while it was opening. A \
             Bluetooth headset does that when its own microphone is opened: it drops \
             from A2DP to HFP, and the speaker does not survive the switch.\n  \
             Capture from somewhere else and the headset stays put — \
             --in \"MacBook Pro Microphone\", or --source tone to use no microphone at all."
        )
    } else {
        format!("open speaker {name}: {e}")
    }
}

/// The default input, unless taking it would drag a headset into narrowband.
///
/// A Bluetooth headset offers a microphone and a speaker as one device, and
/// opening the microphone switches the whole thing from A2DP to HFP. Capture
/// drops to 16 kHz, playback drops with it, and on macOS the speaker often does
/// not survive the switch at all — it fails with "Sample rate update timed out"
/// while the profile changes underneath it. The system default input is that
/// headset whenever one is connected, so the default is the trap.
///
/// The tell is that the default input and the default output are the same
/// device. When they are and a separate microphone exists, that one is used and
/// the substitution is announced — silently choosing a different microphone
/// than the system default would be worse than the problem it avoids.
///
/// `--in` overrides this entirely: naming a device means the caller has decided.
fn default_capture(host: &cpal::Host) -> Result<cpal::platform::Device, String> {
    let default_in = host
        .default_input_device()
        .ok_or_else(|| "no input device — is a microphone connected?".to_string())?;
    let in_name = describe(&default_in);
    let out_name = host
        .default_output_device()
        .map(|d| describe(&d))
        .unwrap_or_default();

    // Different devices, or names we cannot read: nothing to be clever about.
    if in_name == "unnamed device" || in_name != out_name {
        return Ok(default_in);
    }

    let Ok(devices) = host.devices() else {
        return Ok(default_in);
    };
    // Prefer something that reads as built in. Any other input would dodge the
    // profile switch, but a virtual or loopback device would be a worse
    // microphone than the headset, and this is being chosen without being asked.
    let mut fallback = None;
    for d in devices {
        if !d.supports_input() {
            continue;
        }
        let name = describe(&d);
        if name == in_name {
            continue;
        }
        let lower = name.to_lowercase();
        if lower.contains("macbook") || lower.contains("built-in") || lower.contains("internal") {
            eprintln!(
                "capturing from {name} rather than {in_name}: opening a headset's own \
                 microphone switches it to narrowband and can stop its speaker opening at \
                 all. Pass --in {in_name:?} to use it anyway."
            );
            return Ok(d);
        }
        fallback.get_or_insert(d);
    }
    Ok(fallback.unwrap_or(default_in))
}

/// whole point of naming a device is that the default was wrong.
fn pick_device(
    want: Option<&str>,
    input: bool,
) -> Result<cpal::platform::Device, String> {
    let host = cpal::default_host();
    let Some(want) = want else {
        return if input {
            default_capture(&host)
        } else {
            host.default_output_device()
                .ok_or_else(|| "no output device".to_string())
        };
    };

    let needle = want.to_lowercase();
    let mut seen = Vec::new();
    for device in host.devices().map_err(|e| format!("list devices: {e}"))? {
        let usable = if input {
            device.supports_input()
        } else {
            device.supports_output()
        };
        if !usable {
            continue;
        }
        let name = describe(&device);
        if name.to_lowercase().contains(&needle) {
            return Ok(device);
        }
        seen.push(name);
    }
    Err(format!(
        "no {} device matching {want:?}. Available: {}",
        if input { "input" } else { "output" },
        if seen.is_empty() {
            "none".to_string()
        } else {
            seen.join(", ")
        }
    ))
}

/// Print every device and the rates it offers, so the next problem of this
/// shape can be diagnosed without reading this file.
pub fn list_devices() -> Result<(), String> {
    let host = cpal::default_host();
    let default_in = host.default_input_device().map(|d| describe(&d));
    let default_out = host.default_output_device().map(|d| describe(&d));

    for (heading, input) in [("Inputs", true), ("Outputs", false)] {
        println!("{heading}:");
        let mut any = false;
        for device in host.devices().map_err(|e| format!("list devices: {e}"))? {
            let usable = if input {
                device.supports_input()
            } else {
                device.supports_output()
            };
            if !usable {
                continue;
            }
            any = true;
            let name = describe(&device);
            let default = if Some(&name) == (if input { &default_in } else { &default_out }).as_ref()
            {
                "  (default)"
            } else {
                ""
            };
            let configs = if input {
                device.supported_input_configs().map(|c| c.collect::<Vec<_>>())
            } else {
                device.supported_output_configs().map(|c| c.collect::<Vec<_>>())
            };
            match configs {
                Ok(cs) => {
                    let chosen = choose(cs.clone().into_iter(), &name, "audio");
                    let mut rates: Vec<String> = cs
                        .iter()
                        .filter(|r| r.sample_format() == SampleFormat::F32)
                        .map(|r| {
                            if r.min_sample_rate() == r.max_sample_rate() {
                                format!("{}", r.min_sample_rate())
                            } else {
                                format!("{}–{}", r.min_sample_rate(), r.max_sample_rate())
                            }
                        })
                        .collect();
                    rates.sort();
                    rates.dedup();
                    println!("  {name}{default}");
                    println!("    offers: {}", if rates.is_empty() { "no f32 formats".into() } else { rates.join(", ") });
                    match chosen {
                        Ok(c) if c.resampling() => println!(
                            "    would run at: {} device, resampled to {}",
                            c.device_hz, c.rate
                        ),
                        Ok(c) => println!("    would run at: {}", c.rate),
                        Err(e) => println!("    unusable: {e}"),
                    }
                }
                Err(e) => println!("  {name}{default}\n    unavailable: {e}"),
            }
        }
        if !any {
            println!("  none");
        }
    }
    Ok(())
}

// ---- checking synthetic audio -----------------------------------------------

/// The frequency of a pure tone, by counting sign changes.
///
/// Enough to tell whether a 440 Hz sine survived a trip through a codec and a
/// relay, and it needs no FFT: such a sine crosses zero 880 times a second.
/// Only meaningful for a single tone — on speech it measures nothing useful.
pub fn dominant_hz(samples: &[f32]) -> f32 {
    let crossings = samples
        .windows(2)
        .filter(|w| (w[0] < 0.0) != (w[1] < 0.0))
        .count();
    (crossings as f32 / 2.0) * (SAMPLE_RATE as f32 / samples.len() as f32)
}

/// How much of one specific frequency is present, as an amplitude.
///
/// [`dominant_hz`] cannot read a mix — zero crossings only describe a single
/// tone — and a room is several tones at once. This is the Goertzel algorithm:
/// one bin of a DFT, about ten lines, and no FFT dependency for what is only
/// ever used to ask "is that person's tone in here?".
///
/// Returns roughly the amplitude of that component, so a 0.5-amplitude sine at
/// `hz` reads about 0.5 and a frequency that is absent reads about 0.
pub fn amplitude_at(samples: &[f32], hz: f32) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let k = (samples.len() as f32 * hz / SAMPLE_RATE as f32).round();
    let w = std::f32::consts::TAU * k / samples.len() as f32;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0.0f32, 0.0f32);
    for x in samples {
        let s0 = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    2.0 * power.max(0.0).sqrt() / samples.len() as f32
}

/// Root mean square: how loud a stretch of audio is, regardless of its shape.
pub fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}

/// A 440 Hz sine at 48 kHz in 20 ms frames, for tests and for `--source tone`.
pub fn tone(frames: usize) -> Vec<Vec<f32>> {
    tone_frames().take(frames).collect()
}

/// The same, at a frequency of your choosing — so several people in a room can
/// each be a different note and the mix can be checked note by note.
pub fn tone_at(hz: f32, frames: usize) -> Vec<Vec<f32>> {
    sine(hz).take(frames).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tone_is_the_frequency_it_claims_and_does_not_click() {
        let audio: Vec<f32> = tone_frames().take(50).flatten().collect();
        assert_eq!(audio.len(), FRAME_SAMPLES * 50, "one second of it");
        assert!(
            (dominant_hz(&audio) - TONE_HZ).abs() < 2.0,
            "expected {TONE_HZ} Hz, measured {}",
            dominant_hz(&audio)
        );
        // Continuity across the frame seam: a phase reset would show up as a
        // step far larger than one sample's worth of a 440 Hz sine.
        let step = std::f32::consts::TAU * TONE_HZ / SAMPLE_RATE as f32;
        for seam in 1..50 {
            let i = seam * FRAME_SAMPLES;
            assert!(
                (audio[i] - audio[i - 1]).abs() < step,
                "click at frame seam {seam}"
            );
        }
    }

    #[test]
    fn a_single_frequency_can_be_picked_out_of_a_mix() {
        let n = FRAME_SAMPLES * 25;
        let a: Vec<f32> = sine(440.0).take(25).flatten().collect();
        let b: Vec<f32> = sine(660.0).take(25).flatten().collect();
        let mixed: Vec<f32> = a.iter().zip(&b).map(|(x, y)| (x + y) / 2.0).collect();
        assert_eq!(mixed.len(), n);

        // Each tone is present at about a quarter (0.5 amplitude, halved by
        // the mix), and a note nobody is playing is not.
        assert!((amplitude_at(&mixed, 440.0) - 0.25).abs() < 0.02);
        assert!((amplitude_at(&mixed, 660.0) - 0.25).abs() < 0.02);
        assert!(amplitude_at(&mixed, 880.0) < 0.02, "nobody played an A");
    }

    #[test]
    fn wav_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("sqex-voice-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tone.wav");

        let out = wav_writer(&path).unwrap();
        for frame in tone_frames().take(50) {
            out.play(&frame);
        }
        out.finish().unwrap();

        let back: Vec<f32> = wav_frames(&path).unwrap().flatten().collect();
        assert_eq!(back.len(), FRAME_SAMPLES * 50);
        assert!(
            (dominant_hz(&back) - TONE_HZ).abs() < 2.0,
            "the tone did not survive the file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The claim the whole rate design rests on: an Opus stream carries no
    /// obligation about the rate it is decoded at, so two ends of a call never
    /// have to agree and nothing has to be negotiated. Asserted rather than
    /// believed, because if it were false the design would fail as narrowband
    /// nonsense rather than as an error.
    #[test]
    fn a_stream_encoded_at_16k_decodes_correctly_at_48k() {
        let low = Rate::new(16_000).unwrap();
        let high = Rate::DEFAULT;

        let mut enc =
            opus::Encoder::new(low.hz(), opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        let mut dec = opus::Decoder::new(high.hz(), opus::Channels::Mono).unwrap();

        // A 440 Hz tone generated at the *capture* rate, as a 16 kHz mic would.
        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * TONE_HZ / low.hz() as f32;
        let mut out: Vec<f32> = Vec::new();
        let mut pcm = vec![0f32; high.frame()];
        for _ in 0..50 {
            let frame: Vec<f32> = (0..low.frame())
                .map(|_| {
                    let s = phase.sin() * 0.5;
                    phase = (phase + step) % std::f32::consts::TAU;
                    s
                })
                .collect();
            let packet = enc.encode_vec_float(&frame, 1024).unwrap();
            let n = dec.decode_float(&packet, &mut pcm, false).unwrap();
            assert_eq!(n, high.frame(), "decoded at the playback rate, not the encoder's");
            out.extend_from_slice(&pcm[..n]);
        }

        // One second in at 16 kHz is one second out at 48 kHz.
        assert_eq!(out.len(), high.frame() * 50);
        let steady = &out[high.frame() * 3..];
        assert!(
            (dominant_hz(steady) - TONE_HZ).abs() < 5.0,
            "expected {TONE_HZ} Hz, measured {}",
            dominant_hz(steady)
        );
    }

    /// What Opus actually emits with discontinuous transmission on.
    ///
    /// Reports rather than asserts, like the carriage measurement in sqexd:
    /// the numbers inform the design and should not gate CI.
    /// `cargo test -p sqex-voice -- --ignored --nocapture dtx`
    #[test]
    #[ignore = "reports numbers; run explicitly"]
    fn dtx_packet_sizes() {
        let rate = Rate::DEFAULT;
        let mut enc =
            opus::Encoder::new(rate.hz(), opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        enc.set_dtx(true).unwrap();

        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * TONE_HZ / rate.hz() as f32;
        let mut sizes = Vec::new();
        for i in 0..200 {
            let speaking = !(50..150).contains(&i);
            let pcm: Vec<f32> = (0..rate.frame())
                .map(|_| {
                    let s = if speaking { phase.sin() * 0.5 } else { 0.0 };
                    phase = (phase + step) % std::f32::consts::TAU;
                    s
                })
                .collect();
            sizes.push((i, enc.encode_vec_float(&pcm, 1024).unwrap().len()));
        }
        let of = |r: std::ops::Range<usize>| -> Vec<usize> {
            sizes.iter().filter(|(i, _)| r.contains(i)).map(|(_, l)| *l).collect()
        };
        let speech = of(0..50);
        // Skip the first ten silent frames: the encoder takes a moment to decide.
        let silence = of(60..150);
        let mean = |v: &[usize]| v.iter().sum::<usize>() / v.len();

        println!("\n  Opus DTX, 20 ms frames at 24 kbit/s:");
        println!("    speech  : mean {} bytes", mean(&speech));
        println!("    silence : mean {} bytes", mean(&silence));
        println!(
            "    silent frames of <= 2 bytes: {}/{}",
            silence.iter().filter(|l| **l <= 2).count(),
            silence.len()
        );
        println!("    first 20 of the silent run: {:?}\n", &silence[..20]);
    }

    #[test]
    fn a_rate_is_only_one_opus_will_accept() {
        assert_eq!(Rate::new(48_000).unwrap().frame(), 960);
        assert_eq!(Rate::new(16_000).unwrap().frame(), 320);
        assert_eq!(Rate::new(8_000).unwrap().frame(), 160);
        assert!(Rate::new(44_100).is_none(), "Opus does not speak 44.1");
        assert!(Rate::new(0).is_none());
        assert_eq!(Rate::DEFAULT.hz(), SAMPLE_RATE);
        assert_eq!(format!("{}", Rate::DEFAULT), "48 kHz");
    }

    fn range(channels: u16, min: u32, max: u32) -> SupportedStreamConfigRange {
        SupportedStreamConfigRange::new(
            channels,
            min,
            max,
            cpal::SupportedBufferSize::Unknown,
            SampleFormat::F32,
        )
    }

    #[test]
    fn a_device_gets_the_best_rate_opus_and_it_both_speak() {
        // The ordinary case.
        let c = choose([range(1, 48_000, 48_000)].into_iter(), "d", "capture").unwrap();
        assert_eq!(c.rate.hz(), 48_000);
        assert!(!c.resampling());

        // A Bluetooth headset in HFP: the case that started all this. It used
        // to be refused outright.
        let c = choose([range(1, 16_000, 16_000)].into_iter(), "d", "capture").unwrap();
        assert_eq!(c.rate.hz(), 16_000);
        assert!(!c.resampling(), "16 kHz is a rate Opus speaks; no resampler");

        // A wide range takes the best of it.
        let c = choose([range(2, 8_000, 48_000)].into_iter(), "d", "capture").unwrap();
        assert_eq!(c.rate.hz(), 48_000);

        // Fewest channels wins among ranges that all cover the rate.
        let c = choose(
            [range(2, 48_000, 48_000), range(1, 48_000, 48_000)].into_iter(),
            "d",
            "capture",
        )
        .unwrap();
        assert_eq!(c.config.channels, 1);
    }

    #[test]
    fn a_device_speaking_no_opus_rate_is_resampled_rather_than_refused() {
        let c = choose([range(2, 44_100, 44_100)].into_iter(), "d", "playback").unwrap();
        assert_eq!(c.device_hz, 44_100, "the device runs at its own rate");
        assert_eq!(c.rate, Rate::DEFAULT, "the codec runs at 48");
        assert!(c.resampling());
        assert_eq!(c.config.sample_rate, 44_100);
    }

    /// A real device, and the reason quality is ranked before convenience: a
    /// Bluetooth headset offers 44.1 kHz on A2DP and 16 kHz on HFP. Choosing 16
    /// because Opus speaks it would drag the headset into narrowband to save a
    /// resampler nobody asked to save.
    #[test]
    fn a_headset_offering_both_is_not_dragged_into_narrowband() {
        let c = choose(
            [range(1, 16_000, 16_000), range(2, 44_100, 44_100)].into_iter(),
            "ACCENTUM Plus",
            "playback",
        )
        .unwrap();
        assert_eq!(c.device_hz, 44_100, "high quality, not the convenient rate");
        assert!(c.resampling(), "and pay for it with a resampler");
    }

    /// Nothing above 48 kHz buys anything, since that is as much as Opus will
    /// encode — so a 96 kHz device is asked for 48 rather than indulged.
    #[test]
    fn a_device_offering_more_than_opus_needs_is_asked_for_48() {
        let c = choose([range(1, 44_100, 96_000)].into_iter(), "d", "playback").unwrap();
        assert_eq!(c.device_hz, 48_000);
        assert!(!c.resampling());
    }

    /// And one that offers *only* rates above 48 kHz still works, resampled.
    #[test]
    fn a_device_that_only_goes_high_is_still_usable() {
        let c = choose([range(1, 88_200, 96_000)].into_iter(), "d", "playback").unwrap();
        assert_eq!(c.device_hz, 88_200, "the cheapest of its options");
        assert_eq!(c.rate, Rate::DEFAULT);
        assert!(c.resampling());
    }

    #[test]
    fn a_device_with_no_f32_at_all_is_refused_clearly() {
        let err = choose(std::iter::empty(), "Wombat Audio", "capture").unwrap_err();
        assert!(err.contains("Wombat Audio"), "{err}");
        assert!(err.contains("f32"), "{err}");
    }

    #[test]
    fn resampling_preserves_the_tone_and_the_duration() {
        let one_second: Vec<f32> = tone_frames().take(50).flatten().collect();

        let at_44 = resample(&one_second, 48_000, 44_100);
        assert!(
            (at_44.len() as i64 - 44_100).abs() < 100,
            "a second should stay a second: {} samples",
            at_44.len()
        );
        // Reading 440 Hz out of it needs the measurement to know the new rate,
        // so scale the expectation rather than the signal.
        let scaled = dominant_hz(&at_44) * (44_100.0 / SAMPLE_RATE as f32);
        assert!((scaled - TONE_HZ).abs() < 5.0, "measured {scaled}");

        let back = resample(&at_44, 44_100, 48_000);
        assert!((back.len() as i64 - 48_000).abs() < 100);
        assert!(
            (dominant_hz(&back) - TONE_HZ).abs() < 5.0,
            "measured {}",
            dominant_hz(&back)
        );
    }

    #[test]
    fn resampling_to_the_same_rate_changes_nothing() {
        let audio: Vec<f32> = tone_frames().take(2).flatten().collect();
        assert_eq!(resample(&audio, 48_000, 48_000), audio);
        assert!(resample(&[], 48_000, 16_000).is_empty());
    }

    #[test]
    fn a_file_at_the_wrong_rate_is_refused_rather_than_mangled() {
        let dir = std::env::temp_dir().join(format!("sqex-voice-rate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("slow.wav");
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 44_100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut w = hound::WavWriter::create(&path, spec).unwrap();
        w.write_sample(0i16).unwrap();
        w.finalize().unwrap();

        let err = wav_frames(&path).err().expect("should refuse 44.1 kHz");
        assert!(err.contains("44100"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
