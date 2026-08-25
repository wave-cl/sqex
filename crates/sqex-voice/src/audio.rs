//! Where the sound comes from and where it goes.
//!
//! Everything here deals in one shape: a 20 ms mono frame of `f32` at 48 kHz,
//! [`FRAME_SAMPLES`] long. The codec wants exactly that, and keeping the
//! devices, the tone generator and the WAV files all speaking it means the call
//! loop never has to know which of them it is talking to.
//!
//! That interchangeability is the point. A microphone needs hardware, a
//! permission prompt and a person to speak into it; a tone needs none of those,
//! so the same call can be run end to end, checked byte for byte, and put in a
//! test.
//!
//! # Rates
//!
//! Opus accepts 8, 12, 16, 24 or 48 kHz and nothing else. Rather than carry a
//! resampler for the sake of a demo, a device that will not run at 48 kHz is
//! refused with a message saying what it does offer.

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

/// Open a source. The receiver yields one 20 ms frame at a time and closes when
/// the source runs out — a WAV file reaching its end, or the device going away.
pub fn open_source(source: &Source, seconds: Option<u64>) -> Result<UnboundedReceiver<Vec<f32>>, String> {
    match source {
        Source::Mic => microphone(),
        Source::Tone => Ok(synthetic(tone_frames(), seconds)),
        Source::Wav(path) => Ok(synthetic(wav_frames(path)?, seconds)),
    }
}

/// Open a sink. Dropping it stops the device; [`Output::finish`] closes a WAV
/// file properly, which a drop cannot do.
pub fn open_sink(sink: &Sink) -> Result<Output, String> {
    match sink {
        Sink::Speaker => speaker(),
        Sink::Null => Ok(Output(Written::Nowhere)),
        Sink::Wav(path) => wav_writer(path),
    }
}

// ---- sources ----------------------------------------------------------------

/// A 440 Hz sine, continuous across frames so there is no click at the seam.
fn tone_frames() -> impl Iterator<Item = Vec<f32>> {
    let mut phase = 0.0f32;
    let step = std::f32::consts::TAU * TONE_HZ / SAMPLE_RATE as f32;
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

fn microphone() -> Result<UnboundedReceiver<Vec<f32>>, String> {
    let (tx, rx) = unbounded_channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<String, String>>();

    // A cpal stream is not Send on every platform and stops the moment it is
    // dropped, so it lives on a thread of its own that does nothing but hold it.
    std::thread::spawn(move || {
        let report = ready_tx.clone();
        let run = move || -> Result<(), String> {
            let device = cpal::default_host()
                .default_input_device()
                .ok_or("no input device — is a microphone connected?")?;
            let name = describe(&device);
            let config = choose(
                device
                    .supported_input_configs()
                    .map_err(|e| format!("{name}: {e}"))?,
                &name,
                "capture",
            )?;
            let channels = config.channels as usize;
            let mut pending: Vec<f32> = Vec::with_capacity(FRAME_SAMPLES * 2);
            let stream = device
                .build_input_stream::<f32, _, _>(
                    config,
                    move |data, _| {
                        for group in data.chunks(channels) {
                            pending.push(group.iter().sum::<f32>() / channels as f32);
                        }
                        while pending.len() >= FRAME_SAMPLES {
                            let frame: Vec<f32> = pending.drain(..FRAME_SAMPLES).collect();
                            if tx.send(frame).is_err() {
                                return; // the call ended
                            }
                        }
                    },
                    |e| eprintln!("microphone: {e}"),
                    None,
                )
                .map_err(|e| format!("open microphone: {e}"))?;
            stream.play().map_err(|e| format!("start capture: {e}"))?;
            let _ = ready_tx.send(Ok(name));
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
        Ok(Ok(name)) => {
            eprintln!("capturing from {name}");
            Ok(rx)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("the audio thread died before opening the microphone".into()),
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

fn speaker() -> Result<Output, String> {
    let ring: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::new()));
    let for_device = Arc::clone(&ring);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<String, String>>();

    std::thread::spawn(move || {
        let report = ready_tx.clone();
        let run = move || -> Result<(), String> {
            let device = cpal::default_host()
                .default_output_device()
                .ok_or("no output device")?;
            let name = describe(&device);
            let config = choose(
                device
                    .supported_output_configs()
                    .map_err(|e| format!("{name}: {e}"))?,
                &name,
                "playback",
            )?;
            let channels = config.channels as usize;
            let stream = device
                .build_output_stream::<f32, _, _>(
                    config,
                    move |data, _| {
                        let mut r = for_device.lock().expect("audio ring");
                        for group in data.chunks_mut(channels) {
                            // Underrun is silence, not a stall: the far end is
                            // simply not talking yet.
                            let s = r.pop_front().unwrap_or(0.0);
                            group.fill(s);
                        }
                    },
                    |e| eprintln!("speaker: {e}"),
                    None,
                )
                .map_err(|e| format!("open speaker: {e}"))?;
            stream.play().map_err(|e| format!("start playback: {e}"))?;
            let _ = ready_tx.send(Ok(name));
            loop {
                std::thread::park();
            }
        };
        if let Err(e) = run() {
            let _ = report.send(Err(e));
        }
    });

    match ready_rx.recv() {
        Ok(Ok(name)) => {
            eprintln!("playing to {name}");
            Ok(Output(Written::Ring(ring)))
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

/// Pick a 48 kHz f32 configuration, preferring the fewest channels — a mono
/// capture needs no downmix, and a mono playback wastes nothing.
fn choose(
    configs: impl Iterator<Item = SupportedStreamConfigRange>,
    device: &str,
    what: &str,
) -> Result<StreamConfig, String> {
    let mut best: Option<SupportedStreamConfigRange> = None;
    let mut rates: Vec<String> = Vec::new();
    for range in configs {
        if range.sample_format() != SampleFormat::F32 {
            continue;
        }
        rates.push(format!(
            "{}–{}",
            range.min_sample_rate(),
            range.max_sample_rate()
        ));
        if range.min_sample_rate() > SAMPLE_RATE || range.max_sample_rate() < SAMPLE_RATE {
            continue;
        }
        if best.as_ref().is_none_or(|b| range.channels() < b.channels()) {
            best = Some(range);
        }
    }
    let range = best.ok_or_else(|| {
        rates.sort();
        rates.dedup();
        format!(
            "{device} offers no {what} at {SAMPLE_RATE} Hz in f32 (it offers {}), \
             and this demo carries no resampler",
            if rates.is_empty() {
                "nothing".to_string()
            } else {
                rates.join(", ")
            }
        )
    })?;
    Ok(StreamConfig {
        channels: range.channels(),
        sample_rate: SAMPLE_RATE,
        buffer_size: BufferSize::Default,
    })
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
