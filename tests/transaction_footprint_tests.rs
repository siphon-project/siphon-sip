//! What a client transaction costs while it is alive.
//!
//! A proxy holds one per in-flight request for up to 32 s — Timer B/D
//! (RFC 3261 §17.1.1), Timer F (§17.1.2) — purely so it can retransmit. At
//! 10k cps that is ~320k of them resident at once, which makes the per-object
//! figure a capacity number rather than a curiosity: every byte here is 320 MB
//! of RSS on an 8-core box.
//!
//! The measurement is a counting `#[global_allocator]`, for two reasons the
//! obvious instruments get wrong:
//!   * jemalloc's own stats read ~0 here. `#[global_allocator]` is set in
//!     `main.rs` only, so test binaries run on the system allocator and
//!     `tikv_jemalloc_ctl::stats::allocated` never sees these allocations.
//!   * RSS reads 0 for every arm after the first. It does not shrink when an
//!     arm drops, so the later arms allocate into pages the first one already
//!     made resident. A counting allocator is order-independent and exact.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Counts live bytes while armed. The arming flag is global, so the measuring
/// tests run one at a time behind a mutex.
struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            BYTES.fetch_sub(
                layout.size().min(BYTES.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            if new_size >= layout.size() {
                BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            } else {
                BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Live bytes attributable to `body`.
fn measure<T>(body: impl FnOnce() -> T) -> (T, usize) {
    BYTES.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let value = body();
    ARMED.store(false, Ordering::Relaxed);
    (value, BYTES.load(Ordering::Relaxed))
}

use bytes::Bytes;
use siphon::sip::message::SipMessage;
use siphon::sip::parser::parse_sip_message_bytes;
use siphon::transaction::state::{Ict, IctState, Transport};
use siphon::transaction::timer::TimerConfig;
use siphon::transaction::Transaction;

/// The measuring tests share one global arming flag, so they must not overlap.
static SERIALISE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Population size. Large enough that the per-transaction figure is not one
/// lucky allocation, and that the holding `Vec`'s own doublings amortise away.
const POPULATION: usize = 20_000;

/// A representative INVITE with SDP — the shape a proxy retains per call.
const INVITE: &str = concat!(
    "INVITE sip:bob@example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-524287-1---7b9dcc4e4f0e3f2a;rport\r\n",
    "Max-Forwards: 70\r\n",
    "Contact: <sip:alice@192.0.2.10:5060;transport=udp>\r\n",
    "To: <sip:bob@example.com>\r\n",
    "From: <sip:alice@example.com>;tag=8a3f1c2b\r\n",
    "Call-ID: 9f2e1d4c8b7a6f5e3d2c1b0a9876543\r\n",
    "CSeq: 1 INVITE\r\n",
    "Allow: INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,UPDATE,PRACK,REFER,NOTIFY,MESSAGE\r\n",
    "Supported: replaces,100rel,timer,path,outbound\r\n",
    "Session-Expires: 1800\r\n",
    "User-Agent: probe/1.0\r\n",
    "P-Asserted-Identity: <sip:alice@example.com>\r\n",
    "Record-Route: <sip:192.0.2.1;lr>\r\n",
    "Content-Type: application/sdp\r\n",
    "Content-Length: 320\r\n",
    "\r\n",
    "v=0\r\n",
    "o=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 0 8 9 96 97 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:9 G722/8000\r\n",
    "a=rtpmap:96 opus/48000/2\r\n",
    "a=rtpmap:97 AMR-WB/16000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=fmtp:101 0-16\r\n",
    "a=sendrecv\r\n",
    "a=ptime:20\r\n",
);

/// The shape the INVITE client transaction had before it retained octets: the
/// same fields, with the request kept as a parse.
///
/// This is the control arm, and it is the whole point of the file — an absolute
/// byte count on its own says nothing about whether the representation is the
/// cheap one, and it drifts with the fixture and the allocator's size classes.
/// Measured in the same run against the same INVITE, the ratio does not.
#[allow(dead_code)]
struct ParsedShapeIct {
    state: IctState,
    transport: Transport,
    timers: TimerConfig,
    request: SipMessage,
    timer_a_interval: std::time::Duration,
    cached_ack: Option<SipMessage>,
}

/// Cost of one live INVITE client transaction, against the cost of the same
/// transaction holding a parsed request.
///
/// Both arms are boxed exactly as `TransactionManager` stores them, so the
/// figures include the box. They exclude the `DashMap` bucket, which is 80
/// bytes and — being `hashbrown` — sized for peak live entries and never
/// shrunk: a separate retention, already documented on `TransactionManager`,
/// and not one this representation can move.
#[test]
fn client_transaction_retains_octets_not_a_parse() {
    let _guard = SERIALISE.lock().unwrap_or_else(|error| error.into_inner());
    let raw = INVITE.as_bytes();

    // Warm the allocator so arena setup is not charged to the first arm.
    {
        let warm: Vec<SipMessage> = (0..2_000)
            .map(|_| parse_sip_message_bytes(raw).expect("fixture must parse"))
            .collect();
        std::hint::black_box(&warm);
    }

    let (held, octet_bytes) = measure(|| {
        let held: Vec<Box<Transaction>> = (0..POPULATION)
            .map(|_| {
                // A fresh frame per transaction: in production each relay
                // serializes its own request, so sharing one buffer across the
                // population would measure a `Bytes` refcount instead of a
                // retained message.
                let wire = Bytes::from(raw.to_vec());
                let (ict, actions) = Ict::new(wire, Transport::Udp, TimerConfig::default());
                drop(actions);
                Box::new(Transaction::Ict(ict))
            })
            .collect();
        held
    });
    // The retained frame must still be the octets handed in — a transaction
    // that kept something else could not retransmit byte-identically, and the
    // figure above would be measuring the wrong thing.
    match held.first().map(|boxed| &**boxed) {
        Some(Transaction::Ict(ict)) => assert_eq!(ict.request_bytes, raw),
        _ => panic!("expected an INVITE client transaction"),
    }
    drop(held);

    let (control, parsed_bytes) = measure(|| {
        let held: Vec<Box<ParsedShapeIct>> = (0..POPULATION)
            .map(|_| {
                Box::new(ParsedShapeIct {
                    state: IctState::Calling,
                    transport: Transport::Udp,
                    timers: TimerConfig::default(),
                    request: parse_sip_message_bytes(raw).expect("fixture must parse"),
                    timer_a_interval: std::time::Duration::from_millis(500),
                    cached_ack: None,
                })
            })
            .collect();
        held
    });
    drop(control);

    let per_octets = octet_bytes / POPULATION;
    let per_parsed = parsed_bytes / POPULATION;
    // The enum slot is paid whichever variant is in it, so it is the floor a
    // client transaction cannot get under — and it is set by the INVITE *server*
    // transaction's parsed request, not by anything on the client side.
    let enum_slot = std::mem::size_of::<Transaction>();
    eprintln!(
        "INVITE client transaction: {per_octets} bytes live holding the {} wire octets \
         ({enum_slot} of it the Transaction enum slot), {per_parsed} bytes holding the parse \
         ({:.1}x) — at 10k cps x 32 s that is {:.0} MB against {:.0} MB",
        raw.len(),
        per_parsed as f64 / per_octets.max(1) as f64,
        per_octets as f64 * 320_000.0 / 1e6,
        per_parsed as f64 * 320_000.0 / 1e6,
    );

    assert!(
        per_octets <= raw.len() + enum_slot + 64,
        "a live INVITE client transaction costs {per_octets} bytes for a {} byte request; \
         it should be the octets, the {enum_slot}-byte enum slot and change, so something \
         is retaining structure again",
        raw.len()
    );
    assert!(
        per_parsed >= per_octets * 3,
        "the parsed control arm costs {per_parsed} bytes against {per_octets}; at under 3x \
         the two representations have converged and this gate no longer proves anything"
    );
}

/// `Transaction` is stored boxed, but its size is still paid on every insert's
/// memcpy and on every table growth, and the largest variant sets it for all
/// four. Pinned so adding a field to any state machine is a deliberate act with
/// a number attached.
///
/// The INVITE server transaction is what sets this today: it keeps the request
/// parsed so it can synthesise a `100 Trying` from it (§8.2.6.2 obliges the
/// response to echo Via/From/To/Call-ID/CSeq). Projecting that down to the
/// handful of header values it actually reads is the next reduction.
#[test]
fn transaction_enum_size() {
    let size = std::mem::size_of::<Transaction>();
    eprintln!(
        "size_of::<Transaction>() = {size} (SipMessage {}, Ict {}, Nict {}, Ist {}, Nist {})",
        std::mem::size_of::<SipMessage>(),
        std::mem::size_of::<Ict>(),
        std::mem::size_of::<siphon::transaction::state::Nict>(),
        std::mem::size_of::<siphon::transaction::state::Ist>(),
        std::mem::size_of::<siphon::transaction::state::Nist>(),
    );
    assert!(
        size <= 440,
        "Transaction is {size} bytes, past the 440 it was measured at; decide whether the \
         field is worth it before raising this"
    );
}
