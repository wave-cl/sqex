//! The client's end of a SIP-30 event stream.
//!
//! One request is sent, once, and its response never finishes: the exchange
//! writes a frame whenever something this account is entitled to see changes.
//! What arrives is a *hint* — "channel X changed", "this profile moved" — and
//! the client answers it with the fetch it already knows how to do. Nothing
//! here decodes a message or decides who may read one.
//!
//! # Why a task, and not the loop
//!
//! Reading is done on a spawned task that owns the stream and posts decoded
//! events down an unbounded channel. The interface loop then drains that
//! channel without awaiting anything, which is what keeps this out of the
//! keyboard's way.
//!
//! It is worth saying why this is spawned when the reconnect deliberately is
//! not. A pending dial is held as a bare future and advanced a slice at a time
//! precisely to avoid a `Send` bound and a task; but that future has to hand
//! back a `Client` the loop then owns, and this one hands back nothing but
//! bytes. It borrows no state, so there is nothing for a task to fight over.
//!
//! # Silence is not health
//!
//! A QUIC connection can survive an exchange that has stopped saying anything,
//! so an event stream that has gone quiet is indistinguishable from one that
//! is working — which is why the exchange sends a heartbeat and why
//! [`Stream::stale`] exists. Without it the connection light would be green
//! over a stream delivering nothing.

use std::time::{Duration, Instant};

use sqex_proto::events::{Event, Framer, Subscribe, VERSION};
use tokio::sync::mpsc;

/// How long a stream may say nothing at all before it is presumed dead.
///
/// Three missed heartbeats. Two would make an ordinary scheduling hiccup look
/// like a failure; much more than three and a client sits watching a stream
/// that stopped.
pub const SILENCE: Duration = Duration::from_secs(60);

/// What one drain of the stream found.
pub struct Drained {
    pub events: Vec<Event>,
    /// The stream is over: the exchange finished it, the connection went, or a
    /// frame arrived that could not be parsed. A caller must resubscribe.
    pub ended: bool,
}

/// Why a subscription could not be opened.
///
/// The two are not the same and must not be treated alike: a refusal proves the
/// exchange is reachable and answering, so backing off from it would put the
/// connection light on amber over a working connection.
#[derive(Debug)]
pub enum Refusal {
    /// The exchange answered, and said no. The body is its stated reason —
    /// a `sqex_proto::refusal::Refusal` from any exchange that speaks them,
    /// and empty when none arrived.
    Status(u16, Vec<u8>),
    /// The exchange did not answer.
    Transport(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Status(s, body) => match sqex_proto::refusal::Refusal::decode(body) {
                Ok(r) => write!(f, "the exchange refused an event stream ({s}): {r}"),
                Err(_) => write!(f, "the exchange refused an event stream ({s})"),
            },
            Refusal::Transport(e) => write!(f, "{e}"),
        }
    }
}

/// A live subscription being read on a background task.
pub struct Stream {
    rx: mpsc::UnboundedReceiver<Event>,
    task: tokio::task::JoinHandle<()>,
    /// When something last arrived, heartbeats included.
    heard: Instant,
}

impl Stream {
    /// Subscribe, and start reading.
    ///
    /// Returns once the exchange has answered, which is the guarantee the whole
    /// design rests on: **by the time this returns, the subscription is
    /// registered**. A caller may therefore reconcile its state afterwards and
    /// know that anything changing during the reconcile is queued rather than
    /// missed. Reconciling first and subscribing after would lose exactly the
    /// window in between, silently.
    pub async fn open(client: &sqnr::Client) -> Result<Stream, Refusal> {
        let body = Subscribe { version: VERSION }.encode();
        let mut stream = client
            .stream("POST", "/events", body)
            .await
            .map_err(Refusal::Transport)?;
        let status = stream.status();
        if status != 200 {
            // Take the exchange's stated reason rather than reporting a bare
            // number: `too_many_streams` says how many are allowed, and
            // `unsupported_version` says which version it speaks. An absent or
            // unreadable body is not worth failing over — the status is still
            // an answer — so it degrades to empty.
            let said = stream.next().await.ok().flatten().unwrap_or_default();
            return Err(Refusal::Status(status, said));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(pump(stream, tx));
        Ok(Stream {
            rx,
            task,
            heard: Instant::now(),
        })
    }

    /// Take everything that has arrived. Never waits.
    pub fn drain(&mut self) -> Drained {
        let mut events = Vec::new();
        let mut ended = false;
        loop {
            match self.rx.try_recv() {
                Ok(e) => events.push(e),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    ended = true;
                    break;
                }
            }
        }
        if !events.is_empty() {
            self.heard = Instant::now();
        }
        Drained { events, ended }
    }

    /// Whether the stream has said nothing for longer than it should have.
    ///
    /// The exchange heartbeats, so quiet is not a state a working stream stays
    /// in. This is the only thing that can tell a live-but-silent exchange from
    /// a working one, and without it a green light would mean nothing.
    pub fn stale(&self) -> bool {
        self.heard.elapsed() > SILENCE
    }
}

impl Drop for Stream {
    /// End the reader with the subscription.
    ///
    /// It would end on its own once the connection behind it went, but a
    /// resubscribe drops this while the old connection is still up, and a task
    /// reading a stream nobody is listening to is a leak per reconnect.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Read frames until the stream breaks, posting each decoded event.
async fn pump(mut stream: sqnr::Stream, tx: mpsc::UnboundedSender<Event>) {
    let mut framer = Framer::new();
    loop {
        let chunk = match stream.next().await {
            Ok(Some(chunk)) => chunk,
            // The exchange finished the response, or the connection went.
            Ok(None) | Err(_) => return,
        };
        // A framing error is fatal to the stream and not to the frame: once a
        // length is wrong we no longer know where the next event starts, and
        // carrying on would be reading noise as events. Dropping the sender
        // here is what tells the loop to resubscribe.
        let Ok(events) = framer.feed(&chunk) else {
            return;
        };
        for e in events {
            if tx.send(e).is_err() {
                return; // nobody is listening any more
            }
        }
    }
}
