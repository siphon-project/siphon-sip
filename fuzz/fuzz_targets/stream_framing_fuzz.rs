#![no_main]

use libfuzzer_sys::fuzz_target;
use siphon::security::DEFAULT_MAX_MESSAGE_BYTES;
use siphon::transport::tcp::{frame_sip_message, FrameVerdict};

// The stream framer decides, from attacker-controlled bytes, how many of them
// make up one message — before any parsing, authentication or rate limiting
// runs. Its invariants are what keep a peer from steering the reader into
// buffering without bound or slicing outside the buffer.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    for limit in [64usize, 4096, DEFAULT_MAX_MESSAGE_BYTES] {
        match frame_sip_message(data, limit) {
            FrameVerdict::Complete { len } => {
                // The caller does `accumulator.split_to(len)`, so a len past
                // the end of the buffer would panic, and a len over the limit
                // would defeat the ceiling.
                assert!(len <= data.len(), "framed {len} bytes out of {}", data.len());
                assert!(len <= limit, "framed {len} bytes over the {limit} limit");
            }
            FrameVerdict::Oversized { declared, header_len } => {
                // The caller parses `accumulator[..header_len]` to address its
                // 513, so the header block must be inside the buffer, and the
                // refusal must be justified by the declared size.
                assert!(
                    header_len <= data.len(),
                    "header block {header_len} bytes out of {}",
                    data.len()
                );
                assert!(declared > limit, "refused {declared} bytes under the {limit} limit");
            }
            FrameVerdict::NeedMore | FrameVerdict::Garbage => {}
        }
    }
});
