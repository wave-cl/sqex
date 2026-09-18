//! What the validator makes of each record at a name, resolver by resolver.
//!
//!     cargo run -p sqex-discovery --example proof -- _sqex.trunk.exchange
//!     RUST_LOG=hickory_resolver=debug cargo run -p sqex-discovery --example proof -- _sqex.squic.org
//!
//! `sqex discover` says whether a zone's answer was Secure; this says what
//! each record's proof was and, with logging on, what hickory made of every
//! packet on the way — which is how the 2026-09-17 outage was read: every
//! resolver marked "failed to connect" with a decoding error, and the proof
//! Bogus, for a chain `dig` called Secure. See `room_for_a_key_rollover`.
//!
//! An optional second argument sets the EDNS payload size to advertise,
//! to see an answer succeed at 4096 that fails at 1232.

use hickory_resolver::config::{CLOUDFLARE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{Resolver, TokioResolver};

async fn show(r: &TokioResolver, name: &str) {
    match r.lookup(name, RecordType::TXT).await {
        Ok(l) => {
            for rec in l.answers() {
                println!("  {:?}  {}", rec.proof, rec.data);
            }
        }
        Err(e) => println!("  error: {e}"),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let name = std::env::args().nth(1).expect("a name to look up");
    let payload: Option<u16> = std::env::args().nth(2).map(|n| n.parse().expect("a size"));

    let mut b = Resolver::builder_tokio().expect("the system DNS configuration");
    b.options_mut().validate = true;
    if let Some(n) = payload {
        b.options_mut().edns_payload_len = n;
    }
    // `SERIAL=1`: one server at a time. hickory's retry-over-TCP on a
    // truncated answer gives up when a second server's truncated UDP
    // answer lands before the TCP retry, which with two or more servers
    // in the pool is every time on a network that clamps DNS over UDP.
    if std::env::var("SERIAL").is_ok() {
        b.options_mut().num_concurrent_reqs = 1;
    }
    println!("system resolvers:");
    show(&b.build().expect("a resolver"), &name).await;

    let servers = ResolverConfig::udp_and_tcp(&CLOUDFLARE).into_parts().2;
    let config = ResolverConfig::from_parts(None, Vec::new(), servers);
    let mut b = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    b.options_mut().validate = true;
    if let Some(n) = payload {
        b.options_mut().edns_payload_len = n;
    }
    println!("cloudflare:");
    show(&b.build().expect("a resolver"), &name).await;

    // A third argument names one resolver to try on its own -- a hosting
    // provider's, say, that answers from outside and caps UDP at 1232.
    if let Some(ip) = std::env::args().nth(3) {
        use hickory_resolver::config::NameServerConfig;
        let ip: std::net::IpAddr = ip.parse().expect("an IP address");
        // A fourth argument `tcp` makes that server TCP-only, for a network
        // that clamps DNS over UDP.
        let tcp_only = std::env::args().nth(4).as_deref() == Some("tcp");
        let mut server = NameServerConfig::udp_and_tcp(ip);
        if tcp_only {
            server
                .connections
                .retain(|c| matches!(c.protocol, hickory_resolver::config::ProtocolConfig::Tcp));
        }
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![server]);
        let mut b = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
        b.options_mut().validate = true;
        b.options_mut().try_tcp_on_error = true;
        if let Some(n) = payload {
            b.options_mut().edns_payload_len = n;
        }
        println!("{ip}:");
        show(&b.build().expect("a resolver"), &name).await;
    }
}
