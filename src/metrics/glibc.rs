//! glibc `malloc` allocator instrumentation — the C-side / CPython-raw-domain
//! memory pool that jemalloc (siphon's Rust `#[global_allocator]`) does **not**
//! serve and therefore cannot see.
//!
//! Because every Rust allocation routes through jemalloc, glibc's own arenas
//! hold *only* C-side allocations: CPython's raw domain (`PyMem_RawMalloc`),
//! libc internals, and any C extension. On a free-threaded-CPython (3.14t)
//! build with many persistently-attached threads, glibc hands each thread that
//! contends on `malloc` its own arena, each grown in 64 MB chunks
//! (`HEAP_MAX_SIZE`) — none of which is reflected in `siphon_memory_*`
//! (jemalloc) or `siphon_python_allocated_blocks` (CPython's mimalloc object
//! heap). These statistics make that pool visible.
//!
//! The source is **`malloc_info(3)`** (the XML stats dump), *not* `mallinfo2(3)`:
//! `mallinfo2` reports the **main arena only**, so it is blind to exactly the
//! per-thread 64 MB arenas this module exists to surface. `malloc_info`
//! aggregates across every arena.
//!
//! Linux/glibc only. Every entry point is a no-op (returns `None`/`false`) on
//! other targets, so callers need no `cfg` of their own.

/// Aggregated glibc `malloc` statistics across all arenas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlibcStats {
    /// Total heap memory glibc holds from the OS across all arenas (non-mmap).
    /// This is the resident "dark pool" — where the 64 MB per-thread arenas
    /// show up. Mirrors `siphon_memory_allocated_bytes` for the C side.
    pub system_bytes: u64,
    /// Free/retained bytes within those arenas (fastbins + remaining free
    /// chunks). High `free` with high `system` while `in_use` stays flat is
    /// arena *retention* (tune `arena_max` / `malloc_trim`), not a leak.
    pub free_bytes: u64,
    /// Live (allocated, not freed) bytes = `system - free`. A steady climb here
    /// under flat call rate is a genuine raw-domain leak.
    pub in_use_bytes: u64,
    /// Bytes served by `mmap` (large allocations), tracked separately from the
    /// per-arena heaps.
    pub mmap_bytes: u64,
    /// Number of arenas (heaps). Climbs as more threads contend on `malloc` —
    /// each new arena is a fresh ~64 MB reservation.
    pub arena_count: u64,
}

/// glibc `mallopt` parameter for the maximum number of arenas (`M_ARENA_MAX`).
/// Defined as `-8` in `malloc.h`; not exposed as a constant by the `libc` crate.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const M_ARENA_MAX: std::os::raw::c_int = -8;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    // `FILE` is opaque; we only ever hold a pointer to it.
    extern "C" {
        /// Open a stream backed by a dynamically-grown in-memory buffer.
        /// After `fclose`, `*bufp` is a `malloc`-ed buffer of `*sizep` bytes
        /// (NUL-terminated) owned by the caller.
        pub fn open_memstream(bufp: *mut *mut c_char, sizep: *mut usize) -> *mut c_void;
        pub fn fclose(stream: *mut c_void) -> c_int;
        /// Write malloc state as XML to `stream`. `options` must be 0.
        pub fn malloc_info(options: c_int, stream: *mut c_void) -> c_int;
        /// Release free heap memory back to the OS. Returns 1 if any was
        /// released, 0 otherwise.
        pub fn malloc_trim(pad: usize) -> c_int;
        /// Tune a malloc parameter. Returns 1 on success, 0 on failure.
        pub fn mallopt(param: c_int, value: c_int) -> c_int;
        pub fn free(ptr: *mut c_void);
    }
}

/// Capture the raw `malloc_info` XML dump. `None` if unavailable (non-glibc, or
/// the memstream could not be created).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn malloc_info_xml() -> Option<String> {
    use std::os::raw::{c_char, c_void};

    // SAFETY: standard `open_memstream` → `malloc_info` → read → `free` dance.
    // `open_memstream` allocates `buf`; `fclose` finalises `buf`/`size`; we read
    // exactly `size` bytes and then `free(buf)`. Each pointer is checked for
    // null before use. The calls themselves allocate via glibc, which perturbs
    // the stats by a small, constant amount — acceptable for a trend gauge.
    unsafe {
        let mut buffer: *mut c_char = std::ptr::null_mut();
        let mut size: usize = 0;
        let stream = ffi::open_memstream(&mut buffer, &mut size);
        if stream.is_null() {
            return None;
        }
        let result = ffi::malloc_info(0, stream);
        // fclose flushes and finalises `buffer`/`size`; the buffer survives it.
        ffi::fclose(stream);
        if result != 0 || buffer.is_null() {
            if !buffer.is_null() {
                ffi::free(buffer as *mut c_void);
            }
            return None;
        }
        let bytes = std::slice::from_raw_parts(buffer as *const u8, size);
        let xml = String::from_utf8_lossy(bytes).into_owned();
        ffi::free(buffer as *mut c_void);
        Some(xml)
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn malloc_info_xml() -> Option<String> {
    None
}

/// Read aggregated glibc allocator statistics. `None` on non-glibc targets or
/// if the `malloc_info` dump could not be obtained/parsed.
pub fn read_stats() -> Option<GlibcStats> {
    let xml = malloc_info_xml()?;
    Some(parse_malloc_info(&xml))
}

/// Cap the number of glibc arenas via `mallopt(M_ARENA_MAX, n)`. This is the
/// primary lever against per-thread-arena retention (each arena is a ~64 MB
/// reservation). Best applied at startup, before the thread pools spin up.
/// Returns `true` if applied. No-op (returns `false`) off glibc.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn set_arena_max(max_arenas: usize) -> bool {
    // SAFETY: `mallopt` is a plain integer-in/integer-out tunable with no
    // aliasing or memory-safety concerns.
    let result = unsafe { ffi::mallopt(M_ARENA_MAX, max_arenas as std::os::raw::c_int) };
    result == 1
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn set_arena_max(_max_arenas: usize) -> bool {
    false
}

/// Return free heap memory to the OS via `malloc_trim(0)`. Pair with
/// `arena_max` to keep the C-side pool bounded and to separate retention from a
/// true leak. Returns `true` if any memory was released. No-op off glibc.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn trim() -> bool {
    // SAFETY: `malloc_trim` only releases free pages; no aliasing concerns.
    let result = unsafe { ffi::malloc_trim(0) };
    result == 1
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn trim() -> bool {
    false
}

/// Parse the `malloc_info` XML into aggregated stats. Kept allocation-free of
/// any XML dependency: `malloc_info`'s schema is stable, so a targeted scan for
/// the grand-total elements is both sufficient and robust. Pure, so it is
/// unit-testable against a captured fixture without a glibc runtime.
///
/// The relevant grand totals appear once, after the per-`<heap>` blocks:
/// `<system type="current" size=…/>` (OS-held arena bytes),
/// `<total type="rest"/>` + `<total type="fast"/>` (free within arenas),
/// `<total type="mmap"/>` (mmap-served). Each grand total is the *last*
/// occurrence of its element, so we take the last match.
fn parse_malloc_info(xml: &str) -> GlibcStats {
    let system_bytes = last_size(xml, "<system type=\"current\"").unwrap_or(0);
    let free_rest = last_size(xml, "<total type=\"rest\"").unwrap_or(0);
    let free_fast = last_size(xml, "<total type=\"fast\"").unwrap_or(0);
    let mmap_bytes = last_size(xml, "<total type=\"mmap\"").unwrap_or(0);
    let free_bytes = free_rest.saturating_add(free_fast);
    let arena_count = xml.matches("<heap nr=").count() as u64;

    GlibcStats {
        system_bytes,
        free_bytes,
        in_use_bytes: system_bytes.saturating_sub(free_bytes),
        mmap_bytes,
        arena_count,
    }
}

/// Find the last XML element beginning with `marker` and return its `size="…"`
/// attribute value. Returns `None` if no such element (with a parseable size)
/// is present.
fn last_size(xml: &str, marker: &str) -> Option<u64> {
    let mut result = None;
    let mut rest = xml;
    while let Some(index) = rest.find(marker) {
        let tail = &rest[index + marker.len()..];
        // Confine the search to this one element (up to its closing `>`).
        if let Some(element_end) = tail.find('>') {
            let element = &tail[..element_end];
            if let Some(size_index) = element.find("size=\"") {
                let after = &element[size_index + "size=\"".len()..];
                if let Some(quote) = after.find('"') {
                    if let Ok(value) = after[..quote].parse::<u64>() {
                        result = Some(value);
                    }
                }
            }
        }
        rest = &rest[index + marker.len()..];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed but structurally faithful `malloc_info` dump with two arenas,
    /// for parsing without a glibc runtime. Sizes are the grand totals at the
    /// end (the last occurrence of each element).
    const FIXTURE: &str = r#"<malloc version="1">
<heap nr="0">
<sizes></sizes>
<total type="fast" count="3" size="240"/>
<total type="rest" count="5" size="4096"/>
<system type="current" size="135168"/>
<system type="max" size="135168"/>
</heap>
<heap nr="1">
<sizes></sizes>
<total type="fast" count="1" size="80"/>
<total type="rest" count="2" size="2048"/>
<system type="current" size="67108864"/>
<system type="max" size="67108864"/>
</heap>
<total type="fast" count="4" size="320"/>
<total type="rest" count="7" size="6144"/>
<total type="mmap" count="2" size="1048576"/>
<system type="current" size="67244032"/>
<system type="max" size="67244032"/>
</malloc>
"#;

    #[test]
    fn parses_grand_totals_across_arenas() {
        let stats = parse_malloc_info(FIXTURE);
        // Grand-total `<system type="current">` = the last one (67244032),
        // NOT a per-heap value — proving we read the aggregate, not main-arena.
        assert_eq!(stats.system_bytes, 67_244_032);
        // free = grand fast (320) + grand rest (6144).
        assert_eq!(stats.free_bytes, 320 + 6144);
        assert_eq!(stats.in_use_bytes, 67_244_032 - (320 + 6144));
        assert_eq!(stats.mmap_bytes, 1_048_576);
        // Two `<heap nr=…>` blocks → two arenas (the 64 MB-class signature).
        assert_eq!(stats.arena_count, 2);
    }

    #[test]
    fn parse_is_robust_to_missing_fields() {
        let stats = parse_malloc_info("<malloc version=\"1\"></malloc>");
        assert_eq!(stats, GlibcStats::default());
    }

    /// On a glibc host, a live read must succeed and report a non-trivial
    /// resident pool with at least the main arena. Skipped off glibc.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn live_read_reports_arenas() {
        let stats = read_stats().expect("malloc_info must be available on glibc");
        assert!(
            stats.system_bytes > 0,
            "glibc must hold some OS memory; got {stats:?}"
        );
        assert!(
            stats.arena_count >= 1,
            "at least the main arena must be present; got {stats:?}"
        );
    }
}
