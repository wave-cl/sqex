-- The schema of the channel database as it stood on the deployed exchange,
-- captured 2026-09-05 from ex running sqexd 0.33.0.
--
-- **Structure only. No rows, and none may ever be added here** — that database
-- holds real conversations.
--
-- This is the fixture for `migration_flow`: a database in this shape is what a
-- release actually meets, and opening it with the current build must bring
-- every table up to the current schema. It caught nothing when it was written,
-- because it was written after the bug it describes; it exists so the next one
-- is caught before a deploy rather than by somebody's chat breaking.
--
-- Update it when a release ships, not when a column is added: its value is
-- being *behind*.

CREATE TABLE attachment (
    channel       BLOB    NOT NULL,
    blob          BLOB    NOT NULL,
    attached      INTEGER NOT NULL,
    expires_after INTEGER NOT NULL,
    uploader      BLOB    NOT NULL,
    PRIMARY KEY (channel, blob)
);
CREATE TABLE blob (
    id     BLOB PRIMARY KEY,
    size   INTEGER NOT NULL,
    chunks INTEGER NOT NULL
);
CREATE TABLE blob_chunk (
    blob   BLOB    NOT NULL,
    idx    INTEGER NOT NULL,
    sealed BLOB    NOT NULL,
    PRIMARY KEY (blob, idx)
);
CREATE TABLE chain (
    channel   BLOB    NOT NULL,
    device    BLOB    NOT NULL,
    chain_seq INTEGER NOT NULL,
    head      BLOB    NOT NULL,
    PRIMARY KEY (channel, device)
);
CREATE TABLE channel (
    id             BLOB PRIMARY KEY,
    visibility     INTEGER NOT NULL,
    retention_secs INTEGER NOT NULL,
    max_entries    INTEGER NOT NULL,
    name           TEXT    NOT NULL,
    topic          TEXT    NOT NULL,
    epoch          INTEGER NOT NULL,
    next_seq       INTEGER NOT NULL,
    creator        BLOB    NOT NULL,
    created        INTEGER NOT NULL,
    empty_since    INTEGER,
    -- When the current epoch was minted. SIP-17 lets a member who is not an
    -- admin advance the epoch when it revoked one of its own devices *since*
    -- this moment, so the exchange has to hold the moment.
    epoch_at       INTEGER NOT NULL DEFAULT 0,
    -- SIP-31: which incarnation of this identifier this is. A direct message's
    -- id derives from its two accounts, so a destroyed one is recreated under
    -- the same 32 bytes with its numbering restarted; without this marker in
    -- every signature, the previous incarnation's entries verify against this
    -- one. Proposed by the creator, because it has to be signed over before the
    -- exchange has minted anything.
    instance       BLOB    NOT NULL
, head BLOB NOT NULL DEFAULT x'');
CREATE TABLE cursor (
    channel   BLOB    NOT NULL,
    account   BLOB    NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    read      INTEGER NOT NULL DEFAULT 0,
    receipts  INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (channel, account)
);
CREATE TABLE entry (
    channel       BLOB    NOT NULL,
    seq           INTEGER NOT NULL,
    kind          INTEGER NOT NULL,
    account       BLOB    NOT NULL,
    device        BLOB    NOT NULL,
    posted        INTEGER NOT NULL,
    expires_after INTEGER NOT NULL,
    epoch         INTEGER NOT NULL,
    msg_seq       INTEGER NOT NULL,
    -- SIP-31. `chain_seq` is a chain position and deliberately not `msg_seq`,
    -- which is an AEAD nonce and is 0 in a public channel where a chain still
    -- has to run. `body_hash` is what the signature commits to in place of the
    -- body, so a redaction can take the bytes and leave a signature that still
    -- verifies.
    chain_seq     INTEGER NOT NULL,
    prev          BLOB    NOT NULL,
    body_hash     BLOB    NOT NULL,
    sig           BLOB    NOT NULL,
    body          BLOB    NOT NULL, entry_hash BLOB NOT NULL DEFAULT x'', head BLOB NOT NULL DEFAULT x'', receipt BLOB NOT NULL DEFAULT x'',
    PRIMARY KEY (channel, seq)
);
CREATE TABLE envelope (
    channel    BLOB    NOT NULL,
    recipient  BLOB    NOT NULL,
    -- SIP-32: who put this here, and their signature over it and the place it
    -- was published to. A member used to receive a channel key with no way to
    -- tell who had handed it over.
    publisher  BLOB    NOT NULL DEFAULT x'',
    sig        BLOB    NOT NULL DEFAULT x'',
    epoch      INTEGER NOT NULL,
    from_epoch INTEGER NOT NULL,
    to_epoch   INTEGER NOT NULL,
    prekey_id  INTEGER NOT NULL,
    ephemeral  BLOB    NOT NULL,
    ciphertext BLOB    NOT NULL,
    -- One envelope per recipient per epoch. This is what settles the
    -- direct-message creation race: both ends mint epoch 1 and publish, one
    -- Put wins, and the loser is told so and collects instead.
    PRIMARY KEY (channel, recipient, epoch)
);
CREATE TABLE high_water (
    channel BLOB    NOT NULL,
    device  BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    msg_seq INTEGER NOT NULL,
    PRIMARY KEY (channel, device, epoch)
);
CREATE TABLE member (
    channel BLOB    NOT NULL,
    account BLOB    NOT NULL,
    role    INTEGER NOT NULL,
    joined  INTEGER NOT NULL,
    -- Presence and authority are different things in a public channel, where
    -- an admin who leaves keeps the role: joining and leaving govern reading
    -- and posting, being an admin is attached to the channel. A row with
    -- present = 0 is somebody who administers a room they are not in.
    present INTEGER NOT NULL DEFAULT 1,
    -- Whether this member has ever posted here, which is what the invitation
    -- quota counts. A flag rather than a query over `entry`, because pruning
    -- removes entries and somebody whose only message aged out would look like
    -- a fresh invitation again.
    posted  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel, account)
);
CREATE TABLE replica (
    channel BLOB NOT NULL,
    peer    BLOB NOT NULL,
    PRIMARY KEY (channel, peer)
);
CREATE TABLE replicated (
    channel BLOB PRIMARY KEY,
    origin  BLOB NOT NULL,
    -- The origin's own retention window, reported as the origin's and never as
    -- this exchange's. A replica may hold more than the origin does — it
    -- pulled entries the origin has since pruned, which is half the reason to
    -- replicate — and must not claim those are still available there.
    window_secs INTEGER NOT NULL,
    -- Set when this replica holds two receipts for one position under the
    -- origin's key. It stops accepting entries for the channel and **does not
    -- choose** between the branches: picking one silently converts evidence
    -- into a disagreement between two honest-looking servers.
    equivocation BLOB
);
CREATE TABLE retired_instance (
    channel  BLOB NOT NULL,
    instance BLOB NOT NULL,
    PRIMARY KEY (channel, instance)
);
CREATE TABLE upload (
    id            INTEGER PRIMARY KEY,
    channel       BLOB    NOT NULL,
    uploader      BLOB    NOT NULL,
    size          INTEGER NOT NULL,
    chunks        INTEGER NOT NULL,
    expires_after INTEGER NOT NULL,
    started       INTEGER NOT NULL
);
CREATE TABLE upload_chunk (
    upload INTEGER NOT NULL,
    idx    INTEGER NOT NULL,
    sealed BLOB    NOT NULL,
    PRIMARY KEY (upload, idx)
);
CREATE TABLE welcomed (
    account BLOB PRIMARY KEY,
    at      INTEGER NOT NULL
);
CREATE INDEX entry_by_age ON entry (posted);
