//! A stand-in for the kernel's `NETLINK_XFRM` socket, for the worker tests: it
//! acks every request it is sent with that request's sequence number, after a
//! configurable latency, and can withhold or delay chosen acks.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::worker::{Connect, XfrmTransport};
use super::{NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, NLM_F_DUMP};

/// What the fake kernel does, shared by every socket opened on it.
#[derive(Default)]
pub(crate) struct FakeKernel {
    /// Slept before each receive, like a kernel round trip.
    pub latency: Duration,
    /// The errno (positive) the ack of a message type carries; 0 otherwise.
    pub errno_of: HashMap<u16, i32>,
    /// Acks of this type are never sent (the receive times out).
    pub never_ack: Option<u16>,
    /// Acks of this type arrive late: after the next datagram is sent.
    pub late_ack: Option<u16>,
    /// When set, each receive first takes one permit from here, so a test can
    /// hold a worker inside a kernel round trip.
    pub gate: Option<Mutex<std::sync::mpsc::Receiver<()>>>,
    /// Sockets opened.
    pub opened: AtomicUsize,
    /// Requests received (one per netlink message).
    pub requests: AtomicUsize,
    /// Replies not yet received, across sockets.
    pub undelivered: AtomicUsize,
}

impl FakeKernel {
    /// A `Connect` that opens sockets on this fake kernel.
    pub(crate) fn connect(self: &Arc<Self>) -> Arc<Connect> {
        let kernel = Arc::clone(self);
        Arc::new(move || {
            kernel.opened.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeSocket {
                kernel: Arc::clone(&kernel),
                ready: VecDeque::new(),
                late: Vec::new(),
            }) as Box<dyn XfrmTransport>)
        })
    }
}

struct FakeSocket {
    kernel: Arc<FakeKernel>,
    ready: VecDeque<Vec<u8>>,
    late: Vec<Vec<u8>>,
}

fn reply(message_type: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(NLMSG_HDR_LEN + body.len());
    reply.extend_from_slice(&((NLMSG_HDR_LEN + body.len()) as u32).to_ne_bytes());
    reply.extend_from_slice(&message_type.to_ne_bytes());
    reply.extend_from_slice(&0u16.to_ne_bytes());
    reply.extend_from_slice(&sequence.to_ne_bytes());
    reply.extend_from_slice(&0u32.to_ne_bytes());
    reply.extend_from_slice(body);
    reply
}

impl XfrmTransport for FakeSocket {
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
        // What was held back arrives ahead of the replies to this datagram.
        for late in self.late.drain(..) {
            self.ready.push_back(late);
        }
        let mut offset = 0;
        while offset + NLMSG_HDR_LEN <= datagram.len() {
            let header = &datagram[offset..offset + NLMSG_HDR_LEN];
            let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let message_type = u16::from_ne_bytes([header[4], header[5]]);
            let flags = u16::from_ne_bytes([header[6], header[7]]);
            let sequence = u32::from_ne_bytes([header[8], header[9], header[10], header[11]]);
            self.kernel.requests.fetch_add(1, Ordering::SeqCst);
            let answer = if flags & NLM_F_DUMP == NLM_F_DUMP {
                reply(NLMSG_DONE, sequence, &0i32.to_ne_bytes())
            } else {
                let errno = self
                    .kernel
                    .errno_of
                    .get(&message_type)
                    .copied()
                    .unwrap_or(0);
                let mut body = (-errno).to_ne_bytes().to_vec();
                body.extend_from_slice(header);
                reply(NLMSG_ERROR, sequence, &body)
            };
            if self.kernel.never_ack == Some(message_type) {
                // Never answered.
            } else if self.kernel.late_ack == Some(message_type) {
                self.kernel.undelivered.fetch_add(1, Ordering::SeqCst);
                self.late.push(answer);
            } else {
                self.kernel.undelivered.fetch_add(1, Ordering::SeqCst);
                self.ready.push_back(answer);
            }
            offset += length.max(NLMSG_HDR_LEN).next_multiple_of(4);
        }
        Ok(datagram.len())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(gate) = self.kernel.gate.as_ref() {
            let permit = gate
                .lock()
                .map_err(|_| io::Error::other("fake kernel gate poisoned"))?
                .recv();
            if permit.is_err() {
                return Err(io::Error::other("fake kernel gate closed"));
            }
        }
        if !self.kernel.latency.is_zero() {
            std::thread::sleep(self.kernel.latency);
        }
        let Some(next) = self.ready.pop_front() else {
            // SO_RCVTIMEO passed with nothing to read.
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        self.kernel.undelivered.fetch_sub(1, Ordering::SeqCst);
        buffer[..next.len()].copy_from_slice(&next);
        Ok(next.len())
    }
}
