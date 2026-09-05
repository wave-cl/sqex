//! Every sqexd integration test, in one binary.
//!
//! Cargo turns each `tests/*.rs` into its own crate, with its own full static
//! link of the workspace and its dependency tree — quinn, ring, rusqlite,
//! hickory, tokio. Thirteen of those came to 339 MB of binaries, and on macOS
//! each freshly linked one is security-assessed on first execution before
//! `main` runs: one measured at 68.9 seconds of wall clock for 0.08 seconds of
//! tests. The tests were never the cost; the link and the launch were.
//!
//! So they are modules of a single binary instead. One link, one assessment,
//! and the files themselves are untouched — each still owns its own fixtures
//! and reads exactly as it did as a standalone file.
//!
//! Two things this shares that separate binaries did not, worth knowing before
//! adding a test here: the tests now run in one process, so anything touching
//! process-global state — environment variables, statics — must be serialised
//! rather than assumed isolated, and they run against one file-descriptor
//! budget, so a low `ulimit -n` bites harder here than it did.
//!
//! `common` is declared once, at this root, rather than by each module.
//!
//! The layout is `tests/suite/main.rs`, not `tests/suite.rs`: cargo treats a
//! `tests/<dir>/main.rs` as one test target, and modules then resolve inside
//! that directory. A bare `tests/suite.rs` does not work, because submodules
//! of a crate root are looked up beside it rather than under a folder named
//! after it — `mod admin_flow;` there would mean `tests/admin_flow.rs`, which
//! is exactly the per-file target this merge removes.

mod common;

mod admin_flow;
mod beacon_flow;
mod blob_flow;
mod channel_flow;
mod device_flow;
mod mailbox_flow;
mod private_channel_flow;
mod profile_flow;
mod receipt_flow;
mod room_flow;
mod route_coverage;
mod session_flow;
mod signed_entry_flow;
mod sqnr_flow;
