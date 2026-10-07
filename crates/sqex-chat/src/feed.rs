//! SIP-88 feeds and SIP-89 quoting, from the client's side.
//!
//! Publishing is the straightforward half: read the head, sign at the next
//! serial, post. The reading half is where the design earns itself —
//! `/feed/since` asks about every feed this person follows in one request,
//! which is what SIP-50 said client-side reconstruction could not do.
//!
//! # The follow list is this client's and nobody else's
//!
//! There is no route that tells an exchange what somebody reads, and there is
//! not meant to be: the reading graph is broader than the talking graph that
//! SIP-16 already calls the largest disclosure in the stack. The list lives in
//! this store, travels in SIP-48's sealed backup, and is sent to an exchange
//! only as the question `/feed/since` asks — for as long as it takes to answer
//! and no longer.

use sqex_proto::entry_sig::GENESIS;
use sqex_proto::feed::{
    Append, Appended, DIR_BACKWARD, DIR_FORWARD, Head, Headed, MAX_BODY, MAX_PAGE, MAX_SINCE,
    Moved, Page, Post, Read, STATE_GONE, STATE_MOVED, STATE_RESET, STATE_TRUNCATED, Set, Since,
    Stored, Withdraw,
};
use sqex_proto::message::Body;
use sqnr_core::PubKey;

use crate::client::{Chat, ChatError};

type Result<T> = std::result::Result<T, ChatError>;

/// What a feed looked like when this client last asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    pub account: PubKey,
    pub oldest: u64,
    pub newest: u64,
    /// What this client has read to.
    pub held: u64,
}

impl Standing {
    pub fn behind(&self) -> u64 {
        self.newest.saturating_sub(self.held)
    }
}

/// What a `/feed/since` found, sorted into what a caller does about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caught {
    /// Feeds with posts this client has not read.
    pub moved: Vec<Standing>,
    /// Feeds the exchange will not tell us about: absent, withheld, or whose
    /// owner has blocked us. One answer for all three, by design.
    pub gone: Vec<PubKey>,
    /// Feeds whose oldest post is now above what we hold — a gap no amount of
    /// reading will close, and a reader must be told rather than shown the
    /// remainder as though it were the whole.
    pub truncated: Vec<Standing>,
    /// **Always a fault.** A feed's serial belongs to its author and never
    /// restarts, so an exchange reporting one below what we hold is behind or
    /// lying. Never a new feed.
    pub reset: Vec<Standing>,
    /// Feeds whose home could not be asked. **Not the same as unchanged**,
    /// and a caller that treats it as such has a timeline that silently stops
    /// filling.
    pub unasked: Vec<PubKey>,
}

/// A post resolved from a SIP-89 citation, and what could be told about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cited {
    /// Fetched, and its signature holds.
    Got(Box<Stored>),
    /// Its author withdrew it, or it passed its own timer.
    Withdrawn,
    /// The feed is there and this serial is below its oldest.
    Evicted,
    /// The feed is absent, withheld, or its owner has blocked this reader.
    NoFeed,
    /// Fetched and the signature does not hold under the device it names.
    Forged,
    /// **The feed lives at another exchange** (SIP-89 §Resolving one, step 2).
    ///
    /// Not a failure: the home was found and named, and the walk stops here
    /// because resolving it needs a connection this `Chat` does not have. A
    /// caller that can reach `domain` connects there and resolves it with a
    /// `Chat` of its own; one that cannot shows the citation unresolved.
    ///
    /// This exists because the alternative was answering `Unresolved` for a
    /// feed whose home is known, which is what this client used to do and
    /// which reads to a person as "that post may not exist" rather than as
    /// "it is somewhere I did not look".
    Elsewhere {
        home: PubKey,
        /// How to reach that exchange. **May be empty**, when the exchange
        /// answering knew a key and no name; there is then nothing to dial.
        domain: String,
    },
    /// Nothing could be asked: the home is unreachable, or unknown.
    Unresolved,
}

impl Chat {
    // ---- publishing ------------------------------------------------------

    /// Where this account's own feed has got to.
    pub async fn feed_head(&mut self) -> Result<Headed> {
        let me = self.me;
        self.head_of(&me).await
    }

    /// Where somebody's feed has got to.
    pub async fn head_of(&mut self, account: &PubKey) -> Result<Headed> {
        let body = self
            .post("/feed/head", Head { account: *account }.encode())
            .await?;
        Headed::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Publish a SIP-19 body to this account's own feed.
    ///
    /// **Read the head, sign at `newest + 1`, post.** A refusal costs nothing
    /// — the exchange numbered nothing, so the same body re-signs at whatever
    /// serial it turns out to hold, which is what `publish` does once before
    /// giving up. Two devices of one account racing is the ordinary case this
    /// is for, not an error.
    pub async fn publish(&mut self, body: &Body) -> Result<Appended> {
        let head = self.feed_head().await?;
        self.publish_from(head, body).await
    }

    /// [`Chat::publish`], starting from a head already in hand.
    ///
    /// What a caller appending several posts wants, and **the shape that
    /// makes the losing case reachable**: given a head that has since moved,
    /// the first attempt is refused, this re-reads and signs again, and the
    /// post lands. `publish` is this with a fresh head, so the recovery it
    /// relies on is the one a test can drive deliberately rather than by
    /// winning a race.
    pub async fn publish_from(&mut self, head: Headed, body: &Body) -> Result<Appended> {
        let mut head = head;
        for attempt in 0..2 {
            match self.publish_at(&head, body).await {
                Ok(a) => return Ok(a),
                // Somebody else of ours got there first. Re-read and sign
                // again, once: a second failure is a race this client is
                // losing repeatedly and a caller should hear about it rather
                // than have this spin.
                Err(e) if attempt == 0 && stale(&e) => head = self.feed_head().await?,
                Err(e) => return Err(e),
            }
        }
        Err(ChatError::Protocol(
            "another of your devices is publishing; try again".into(),
        ))
    }

    /// Publish against a head already read.
    ///
    /// The primitive [`Chat::publish`] retries around, and what a caller
    /// wants when it is appending several posts and has the head in hand.
    /// **Refused if the head has moved** — which costs nothing, because the
    /// exchange numbers nothing and the same body re-signs at the serial it
    /// turns out to hold.
    pub async fn publish_at(&mut self, head: &Headed, body: &Body) -> Result<Appended> {
        let bytes = body.encode();
        if bytes.len() > MAX_BODY {
            return Err(ChatError::Protocol(format!(
                "a post is at most {MAX_BODY} bytes, and this is {}",
                bytes.len()
            )));
        }
        let (serial, prev) = if head.found {
            (head.newest + 1, head.head_input)
        } else {
            (1, GENESIS)
        };
        let post = Post::sign(
            &self.seed,
            &self.me,
            serial,
            &prev,
            now(),
            // No per-post timer yet. SIP-88 carries `expires_after` and
            // nothing in this client sets one; a caller that wants a
            // disappearing post needs an argument here, not a default.
            0,
            bytes,
        );
        let body = self.post("/feed/append", Append { post }.encode()).await?;
        Appended::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Withdraw one of this account's own posts, leaving a tombstone.
    ///
    /// **This does not take it back.** It stops this exchange serving the
    /// body; it reaches no reader who already has it, no copy, and no
    /// screenshot. A client MUST say so where a post is composed rather than
    /// in a settings screen.
    pub async fn withdraw(&mut self, serial: u64) -> Result<()> {
        let account = self.me;
        let body = self
            .post("/feed/withdraw", Withdraw { account, serial }.encode())
            .await?;
        sqex_proto::channel::Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }

    /// Set this account's own feed's retention and size, whole.
    pub async fn set_feed(&mut self, retention_secs: u32, max_posts: u32) -> Result<()> {
        let body = self
            .post(
                "/feed/set",
                Set {
                    retention_secs,
                    max_posts,
                }
                .encode(),
            )
            .await?;
        sqex_proto::channel::Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }

    // ---- reading ---------------------------------------------------------

    /// A page of somebody's feed, newest first.
    ///
    /// Backward by default because that is how a feed is read: a channel is
    /// caught up to from where you left it, and a feed of ten thousand posts
    /// is arrived at wanting the last twenty.
    pub async fn read_feed(&mut self, account: &PubKey, before: u64, limit: u16) -> Result<Page> {
        self.page_of(account, before, limit, DIR_BACKWARD).await
    }

    /// A page forward from `since`, which is how a follower catches up.
    pub async fn read_feed_after(
        &mut self,
        account: &PubKey,
        since: u64,
        limit: u16,
    ) -> Result<Page> {
        self.page_of(account, since, limit, DIR_FORWARD).await
    }

    async fn page_of(&mut self, account: &PubKey, since: u64, limit: u16, dir: u8) -> Result<Page> {
        let body = self
            .post(
                "/feed/read",
                Read {
                    account: *account,
                    since,
                    limit: limit.clamp(1, MAX_PAGE),
                    dir,
                }
                .encode(),
            )
            .await?;
        let page = Page::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        // **Step one of SIP-31's two, and only step one.** A signature proves
        // a key signed; it says nothing about whose key it is. What is dropped
        // here is a post whose signature does not hold at all, which is the
        // cheap half.
        //
        // The SIP-20 credential binding `device` to `account` is **not checked
        // anywhere**. An earlier version of this comment sent the reader to a
        // `verified_author` that was never written, which is worse than
        // silence: it reads as a reassurance. SIP-89 §Reference implementation
        // records the gap, and closing it belongs here.
        Ok(Page {
            posts: page.posts.into_iter().filter(|s| s.post.verify()).collect(),
            ..page
        })
    }

    /// Follow a feed. Local: no exchange is told.
    pub fn follow(&self, account: &PubKey) -> Result<()> {
        self.store().follow(account, now())?;
        Ok(())
    }

    /// Stop following. Also local.
    pub fn unfollow(&self, account: &PubKey) -> Result<()> {
        self.store().unfollow(account)?;
        Ok(())
    }

    /// Everyone this client follows, with where each was read to.
    pub fn following(&self) -> Result<Vec<(PubKey, u64)>> {
        Ok(self.store().follows()?)
    }

    /// Which of the feeds this person follows have moved.
    ///
    /// One request for up to `MAX_SINCE` feeds, paged past that. SIP-50
    /// rejected the alternative in as many words: "N+1 requests per contact
    /// per poll, and it would still not know about the wake registration."
    pub async fn feeds_since(&mut self) -> Result<Caught> {
        let follows = self.store().follows()?;
        let mut caught = Caught::default();
        for batch in follows.chunks(MAX_SINCE as usize) {
            let body = self
                .post(
                    "/feed/since",
                    Since {
                        feeds: batch.to_vec(),
                    }
                    .encode(),
                )
                .await?;
            let moved = Moved::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            for row in moved.rows {
                let Some((account, held)) = batch.get(row.index as usize).copied() else {
                    // A row naming a position we did not ask about. Nothing
                    // can be done with it and guessing would attribute one
                    // feed's movement to another.
                    continue;
                };
                // The home could not be asked. **Not unchanged** — SIP-60
                // §Saying whose list it is is the precedent, and a caller
                // that conflated the two would have a timeline that stopped
                // filling with nothing to show for it.
                if row.source == sqex_proto::feed::FROM_UNASKED {
                    caught.unasked.push(account);
                    continue;
                }
                let standing = Standing {
                    account,
                    oldest: row.oldest,
                    newest: row.newest,
                    held,
                };
                match row.state {
                    STATE_MOVED => caught.moved.push(standing),
                    STATE_GONE => caught.gone.push(account),
                    STATE_TRUNCATED => caught.truncated.push(standing),
                    STATE_RESET => caught.reset.push(standing),
                    // A state from a later version of SIP-88. Ignored rather
                    // than guessed at: the feed is simply not reported as
                    // having moved, which is the safe direction.
                    _ => {}
                }
            }
        }
        Ok(caught)
    }

    /// Mark a feed read to `serial`. Never moves backwards.
    pub fn read_to(&self, account: &PubKey, serial: u64) -> Result<()> {
        self.store().read_feed_to(account, serial)?;
        Ok(())
    }

    // ---- SIP-89 ----------------------------------------------------------

    /// Resolve a SIP-89 citation: the post it names, or why not.
    ///
    /// **The citation carries no copy of anything.** The account key is both
    /// the locator and the verifying key, so what comes back is checked under
    /// a key this client already holds and no exchange is in the trust path.
    /// A citer who lies produces something that will not resolve rather than
    /// a false attribution, which is the whole reason a pointer was chosen
    /// over a copy.
    pub async fn resolve_quote(&mut self, account: &PubKey, serial: u64) -> Cited {
        if serial == 0 {
            return Cited::Unresolved;
        }
        // **Step 2: find the feed.** A feed lives at its account's home
        // (SIP-88 §Where a feed lives) and that is not necessarily here. Read
        // first and ask afterwards and a feed homed elsewhere comes back as a
        // `moved` refusal, which this client used to report as `Unresolved` --
        // a feed whose home it had been told, described to the reader as a
        // post that might not exist.
        match self.account_home(account).await {
            Ok(homed) if homed.home != self.exchange_key() => {
                return Cited::Elsewhere {
                    home: homed.home,
                    domain: homed.domain,
                };
            }
            // Known here, so read here.
            Ok(_) => {}
            // **A failed lookup falls through rather than failing.** This step
            // can only ever improve an answer: an exchange that does not know
            // where somebody lives answers 404, an exchange too old to carry
            // the route answers the router's own, and `classify` folds both
            // into one error -- so neither can be told from the other here.
            // Reading locally then gives `NoFeed` for an account nobody knows,
            // which is what §When it cannot be resolved asks for, and the
            // right answer for an old exchange too.
            //
            // **Which also means cross-exchange resolution reaches only as far
            // as the reader's own exchange knows.** A citation of somebody who
            // never lived here is unresolvable, and SIP-89's table says to
            // show that as a feed that could not be found rather than to guess
            // an exchange.
            Err(_) => {}
        }
        // Read the one post at `serial`: forward from the one below it.
        let page = match self.page_of(account, serial - 1, 1, DIR_FORWARD).await {
            Ok(p) => p,
            Err(_) => return Cited::Unresolved,
        };
        if !page.found {
            return Cited::NoFeed;
        }
        if serial < page.oldest {
            return Cited::Evicted;
        }
        // `page_of` drops anything whose signature does not hold, so a serial
        // the feed says it has and that is missing here failed exactly that.
        let Some(stored) = page.posts.into_iter().find(|s| s.post.serial == serial) else {
            return if serial <= page.newest {
                Cited::Forged
            } else {
                Cited::Unresolved
            };
        };
        if stored.post.withdrawn() {
            return Cited::Withdrawn;
        }
        Cited::Got(Box::new(stored))
    }
}

/// Whether a refusal was the exchange saying this serial is not the next one.
fn stale(e: &ChatError) -> bool {
    matches!(
        e,
        ChatError::Refused(_, r)
            if r.code == sqex_proto::refusal::Code::StaleSerial
                || r.code == sqex_proto::refusal::Code::BrokenChain
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
