//! Exact per-binding allocation accounting for the registrar.
//!
//! The SIPp harness (`scripts/registrar_scale_test.sh`) measures what a
//! population *costs the box*; this measures what one binding *is*. It runs its
//! own counting global allocator, so the numbers are exact and deterministic
//! rather than a settled RSS reading — which is what makes them usable as a
//! regression gate and as evidence about the floor.
//!
//! This is its own test binary specifically so the `#[global_allocator]` below
//! governs the whole process. A counting allocator installed in the lib test
//! binary would be shared with several thousand unrelated tests running
//! concurrently and would count all of them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Counts allocations and live bytes while armed. Not thread-safe by design of
/// the *measurement* (the arming flag is global), so the measuring tests run
/// one at a time behind a mutex.
struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            // The requested size, not the size class: this is a measure of what
            // the data structures ask for, and a jemalloc/glibc bin rounding is
            // the allocator's contribution, tracked separately by the SIPp
            // harness's resident figure.
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            FREES.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_sub(
                layout.size().min(BYTES.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            // Deliberately not an allocation for counting purposes: a realloc
            // replaces a live block rather than adding one, and the count here
            // is "how many separate blocks does a binding hold", which is what
            // predicts the size-class rounding. Only the size delta moves.
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

/// Live bytes and net allocations attributable to `body`.
fn measure<T>(body: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCS.store(0, Ordering::Relaxed);
    FREES.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let value = body();
    ARMED.store(false, Ordering::Relaxed);
    (
        value,
        ALLOCS.load(Ordering::Relaxed)
            - FREES
                .load(Ordering::Relaxed)
                .min(ALLOCS.load(Ordering::Relaxed)),
        BYTES.load(Ordering::Relaxed),
    )
}

use siphon::registrar::{Contact, Registrar, RegistrarConfig};
use siphon::sip::parser::parse_uri_standalone;

/// Population size. Large enough that the DashMap's bucket array has grown
/// through several doublings, so the per-binding figure includes a
/// representative share of table overhead rather than a lucky moment just
/// after a resize.
const POPULATION: usize = 20_000;

/// The measuring tests share one global arming flag, so they must not overlap.
static SERIALISE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn registrar() -> Registrar {
    Registrar::new(RegistrarConfig {
        default_expires: 3600,
        max_expires: 7200,
        ..Default::default()
    })
}

/// A plain UE binding: what a residential proxy or a no-auth REGISTER load
/// actually stores. No IMS extras, one contact per AoR.
fn save_plain(registrar: &Registrar, index: usize) {
    let uri = parse_uri_standalone(&format!("sip:u{index}@198.51.100.7:5060;transport=udp"))
        .expect("contact uri");
    registrar
        .save(
            &format!("sip:u{index}@example.com"),
            uri,
            3600,
            1.0,
            format!("{index}-call-id@198.51.100.7"),
            1,
        )
        .expect("save");
}

/// Bytes of live data one plain binding costs, and how many separate
/// allocations it is spread across. Both are the figures a change has to move;
/// the allocation count is the one that predicts the resident cost, because
/// each one pays its own size-class rounding.
#[test]
fn plain_binding_footprint() {
    let _guard = SERIALISE.lock().unwrap_or_else(|e| e.into_inner());
    let registrar = registrar();
    // Warm the table past its first few doublings so the measured window is
    // steady-state rather than dominated by one resize.
    for index in 0..POPULATION {
        save_plain(&registrar, index);
    }

    let (_, allocations, bytes) = measure(|| {
        for index in POPULATION..(POPULATION * 2) {
            save_plain(&registrar, index);
        }
    });

    let per_binding_bytes = bytes / POPULATION;
    let per_binding_allocs = allocations as f64 / POPULATION as f64;
    eprintln!(
        "plain binding: {per_binding_bytes} bytes live across {per_binding_allocs:.2} allocations \
         (Contact struct = {} bytes)",
        std::mem::size_of::<Contact>()
    );

    // Ceilings, not targets: they exist so a field added to `Contact` without
    // thought, or a new per-binding allocation, reddens here instead of showing
    // up as a memory report months later. Measured at 526 bytes across 8
    // allocations; the headroom is for allocator and std variation, not for
    // drift. Raise either only with a measurement saying the new cost is worth
    // paying.
    assert!(
        per_binding_bytes <= 560,
        "a plain binding now costs {per_binding_bytes} bytes of live data"
    );
    assert!(
        per_binding_allocs <= 8.0,
        "a plain binding now takes {per_binding_allocs:.2} allocations"
    );
}

/// `Contact` is stored inline in a `Vec` per AoR, so its size is paid by every
/// binding whether or not the fields are populated — an IMS-only `Option` costs
/// the residential deployment too. Pinned so a field addition is a deliberate
/// act with a number attached.
#[test]
fn contact_struct_size() {
    eprintln!("size_of::<Contact>() = {}", std::mem::size_of::<Contact>());
    // 320 is a jemalloc size class, and `Contact` sits exactly on it. That is
    // the whole point of the number: one byte over and every binding's
    // allocation rounds up to the 384 class, so 8 bytes of struct silently
    // costs 64 bytes of resident memory per contact. A field added here is not
    // free even when it looks like it fits.
    assert!(
        std::mem::size_of::<Contact>() <= 320,
        "Contact is {} bytes — over the 320-byte jemalloc size class, so every \
         binding's allocation now rounds up to 384",
        std::mem::size_of::<Contact>()
    );
}

/// What the same binding costs when stored with no structure at all: the three
/// strings SIP obliges us to keep (the AoR, the contact URI, the Call-ID) plus
/// the scalars, in the cheapest container that can still answer a lookup.
///
/// This is the floor, and it exists to keep the optimisation honest. Every byte
/// between this and [`plain_binding_footprint`] is structure — fields a plain
/// binding leaves empty but that exist because `Contact` is one shape serving
/// residential SIP, IMS, outbound registration and Path-token routing at once,
/// plus the per-string allocations that a packed representation would fold into
/// one. Quoting a reduction without this number makes any remaining gap
/// invisible.
#[test]
fn irreducible_floor() {
    let _guard = SERIALISE.lock().unwrap_or_else(|e| e.into_inner());

    // Same shape as the real thing: an AoR-keyed concurrent map. The value is
    // only what the protocol requires — where to reach the user, which dialog
    // created the binding, and when it dies.
    struct Minimal {
        contact_uri: Box<str>,
        call_id: Box<str>,
        expires_secs: u32,
        cseq: u32,
    }
    let store: dashmap::DashMap<Box<str>, Minimal> = dashmap::DashMap::new();

    for index in 0..POPULATION {
        store.insert(
            format!("sip:u{index}@example.com").into_boxed_str(),
            Minimal {
                contact_uri: format!("sip:u{index}@198.51.100.7:5060;transport=udp")
                    .into_boxed_str(),
                call_id: format!("{index}-call-id@198.51.100.7").into_boxed_str(),
                expires_secs: 3600,
                cseq: 1,
            },
        );
    }

    let (_, allocations, bytes) = measure(|| {
        for index in POPULATION..(POPULATION * 2) {
            store.insert(
                format!("sip:u{index}@example.com").into_boxed_str(),
                Minimal {
                    contact_uri: format!("sip:u{index}@198.51.100.7:5060;transport=udp")
                        .into_boxed_str(),
                    call_id: format!("{index}-call-id@198.51.100.7").into_boxed_str(),
                    expires_secs: 3600,
                    cseq: 1,
                },
            );
        }
    });

    // Read it back. A floor that cannot answer the question a registrar exists
    // to answer is not a floor, it is a smaller number — so the comparison only
    // holds if every field measured above is actually reachable by AoR.
    let probe = format!("sip:u{}@example.com", POPULATION + 1);
    let found = store
        .get(probe.as_str())
        .expect("floor store must resolve an AoR");
    assert_eq!(
        &*found.contact_uri,
        format!("sip:u{}@198.51.100.7:5060;transport=udp", POPULATION + 1).as_str()
    );
    assert_eq!(
        &*found.call_id,
        format!("{}-call-id@198.51.100.7", POPULATION + 1).as_str()
    );
    assert_eq!(found.expires_secs, 3600);
    assert_eq!(found.cseq, 1);
    drop(found);

    let floor_bytes = bytes / POPULATION;
    let floor_allocs = allocations as f64 / POPULATION as f64;
    eprintln!(
        "irreducible floor: {floor_bytes} bytes across {floor_allocs:.2} allocations \
         (Minimal struct = {} bytes)",
        std::mem::size_of::<Minimal>()
    );

    // Sanity, not a gate on the floor itself: if this ever exceeds what a real
    // binding costs, the comparison has stopped meaning anything.
    assert!(floor_bytes > 0);
}
