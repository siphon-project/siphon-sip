//! The threads that talk XFRM netlink to the kernel: a fixed set of dedicated
//! workers, each owning one long-lived `NETLINK_XFRM` socket, fed by one
//! bounded queue. Callers enqueue a job and await its reply.
//!
//! Why not `spawn_blocking` per kernel operation: a P-CSCF allocating a pair
//! for every 401 of a re-REGISTER wave runs up to sixteen kernel operations per
//! UE, so thousands of UEs at once asked tokio's blocking pool for thousands of
//! threads. The pool stops at `max_blocking_threads` (512); past that every
//! other blocking job (script completions among them) queues behind the
//! netlink ones, and the process sits at hundreds of threads it never needed.
//! The kernel serialises XFRM configuration on one mutex per network namespace
//! anyway, so more threads bought no throughput. A fixed pool keeps the thread
//! count flat, a bounded queue turns a wave into backpressure that callers
//! await (asynchronously, never parking a tokio worker), and a full queue
//! answers with an error instead of growing without bound.
//!
//! Reusing one socket means a late ack can arrive after its operation was
//! given up on. Every message carries its own sequence number, and a reply is
//! matched on it: a stale reply (an earlier operation's) is read and dropped.
//!
//! The workers never touch the interpreter, so their blocking `recv` holds no
//! garbage collection open.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use netlink_sys::{protocols::NETLINK_XFRM, Socket, SocketAddr};
use tokio::sync::oneshot;
use tracing::{debug, error, warn};

use super::{
    align_to, parse_sa_use_time, NLMSG_ALIGNTO, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, NLM_F_DUMP,
    NLM_F_REQUEST, XFRM_MSG_GETSA, XFRM_MSG_NEWSA,
};
use crate::ipsec::IpsecError;

/// Worker threads of the kernel pool. The kernel takes XFRM configuration
/// under one mutex, so one thread already keeps it busy; the second keeps the
/// queue moving while the first waits out an ack that never comes.
pub(crate) const WORKER_COUNT: usize = 2;
/// Jobs the queue holds before a caller waits for room. A job is one kernel
/// operation, or one batch of them (the deletes before an install).
pub(crate) const QUEUE_CAPACITY: usize = 1024;
/// How long a worker waits for the kernel's reply (`SO_RCVTIMEO`). The local
/// kernel answers in microseconds; this exists so a reply that never comes
/// cannot hold a worker forever.
pub(crate) const ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a caller waits for room in the queue, and the longest a job may
/// sit in it before a worker refuses it unsent.
pub(crate) const QUEUE_WAIT: Duration = Duration::from_secs(5);
/// A dump reply is one datagram per kernel batch, well under this.
const RECV_BUFFER: usize = 64 * 1024;

/// One netlink socket as a worker uses it.
pub(crate) trait XfrmTransport: Send {
    /// Send one datagram (one or more netlink messages); the bytes sent.
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize>;
    /// Receive one datagram into `buffer`; `WouldBlock`/`TimedOut` when the
    /// receive timeout passed with nothing.
    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

/// Opens a worker's socket; called again after the socket failed.
pub(crate) type Connect = dyn Fn() -> io::Result<Box<dyn XfrmTransport>> + Send + Sync;

/// The kernel's `NETLINK_XFRM`, connected, with a receive timeout.
struct KernelSocket(Socket);

impl KernelSocket {
    fn open(timeout: Duration) -> io::Result<Box<dyn XfrmTransport>> {
        let socket = Socket::new(NETLINK_XFRM)?;
        socket.connect(&SocketAddr::new(0, 0))?;
        set_recv_timeout(&socket, timeout)?;
        Ok(Box::new(KernelSocket(socket)))
    }
}

impl XfrmTransport for KernelSocket {
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
        self.0.send(datagram, 0)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.recv(&mut &mut buffer[..], 0)
    }
}

/// `SO_RCVTIMEO` on the raw fd: `netlink-sys` exposes no timeout setter.
fn set_recv_timeout(socket: &Socket, timeout: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
    };
    // SAFETY: plain setsockopt on a socket fd we own, passing a properly sized
    // and initialized `timeval`: no aliasing, no retained pointers.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeval).cast::<libc::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a job asks of the kernel.
enum Work {
    /// Netlink messages (each with `NLM_F_ACK`, sequence left 0) sent in one
    /// datagram; the kernel handles each on its own and acks each.
    Acks(Vec<Vec<u8>>),
    /// Dump every SA's last-active time.
    DumpSa,
}

enum Outcome {
    /// One result per message, in order.
    Acks(Vec<io::Result<()>>),
    Dump(io::Result<HashMap<u32, u64>>),
}

/// Counts a job from the moment it is made until it is answered or dropped.
struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Job {
    work: Work,
    enqueued: Instant,
    reply: oneshot::Sender<Outcome>,
    in_flight: InFlight,
}

/// A fixed pool of netlink workers behind one bounded queue. The threads start
/// with the first job, so a manager that never reaches the kernel starts none.
pub(crate) struct XfrmWorkers {
    connect: Arc<Connect>,
    name: &'static str,
    workers: usize,
    capacity: usize,
    ack_timeout: Duration,
    queue_wait: Duration,
    in_flight: Arc<AtomicUsize>,
    queue: OnceLock<flume::Sender<Job>>,
}

impl XfrmWorkers {
    /// The process's pool on the kernel's sockets.
    pub(crate) fn kernel() -> &'static XfrmWorkers {
        static KERNEL: OnceLock<XfrmWorkers> = OnceLock::new();
        KERNEL.get_or_init(|| {
            XfrmWorkers::new(
                Arc::new(|| KernelSocket::open(ACK_TIMEOUT)),
                "xfrm-netlink",
                WORKER_COUNT,
                QUEUE_CAPACITY,
                ACK_TIMEOUT,
                QUEUE_WAIT,
            )
        })
    }

    /// A pool over `connect`'s sockets. `name` prefixes the thread names
    /// (kept within the kernel's 15 bytes with the index).
    pub(crate) fn new(
        connect: Arc<Connect>,
        name: &'static str,
        workers: usize,
        capacity: usize,
        ack_timeout: Duration,
        queue_wait: Duration,
    ) -> Self {
        Self {
            connect,
            name,
            workers: workers.max(1),
            capacity: capacity.max(1),
            ack_timeout,
            queue_wait,
            in_flight: Arc::new(AtomicUsize::new(0)),
            queue: OnceLock::new(),
        }
    }

    fn sender(&self) -> &flume::Sender<Job> {
        self.queue.get_or_init(|| {
            let (sender, receiver) = flume::bounded(self.capacity);
            for index in 0..self.workers {
                let receiver = receiver.clone();
                let connect = Arc::clone(&self.connect);
                let (ack_timeout, queue_wait) = (self.ack_timeout, self.queue_wait);
                let spawned = std::thread::Builder::new()
                    .name(format!("{}-{index}", self.name))
                    .spawn(move || run(index, &receiver, &connect, ack_timeout, queue_wait));
                if let Err(spawn_error) = spawned {
                    error!(%spawn_error, index, "IPsec: could not start an XFRM netlink worker");
                }
            }
            // With no worker started every send fails as disconnected, which
            // `submit` reports; the receivers live in the workers only.
            sender
        })
    }

    /// Send `messages` in one datagram and return each one's ack, in order.
    /// The outer error means nothing was sent.
    pub(crate) async fn acknowledge(
        &self,
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<Result<(), IpsecError>>, IpsecError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        match self.submit(Work::Acks(messages)).await? {
            Outcome::Acks(results) => Ok(results
                .into_iter()
                .map(|result| {
                    result.map_err(|error| IpsecError::Command(format!("xfrm netlink: {error}")))
                })
                .collect()),
            Outcome::Dump(_) => Err(IpsecError::Command(
                "xfrm netlink: a worker answered an ack job with a dump".to_string(),
            )),
        }
    }

    /// Send one message and return its ack.
    pub(crate) async fn acknowledge_one(&self, message: Vec<u8>) -> Result<(), IpsecError> {
        self.acknowledge(vec![message])
            .await?
            .pop()
            .unwrap_or_else(|| {
                Err(IpsecError::Command(
                    "xfrm netlink: a worker answered without a result".to_string(),
                ))
            })
    }

    /// Dump every XFRM SA's `spi -> last_active_secs`.
    pub(crate) async fn dump_sa_use_times(&self) -> Result<HashMap<u32, u64>, IpsecError> {
        match self.submit(Work::DumpSa).await {
            Ok(Outcome::Dump(result)) => {
                result.map_err(|error| IpsecError::Command(format!("xfrm GETSA dump: {error}")))
            }
            Ok(Outcome::Acks(_)) => Err(IpsecError::Command(
                "xfrm GETSA dump: a worker answered a dump job with acks".to_string(),
            )),
            Err(error) => Err(error),
        }
    }

    async fn submit(&self, work: Work) -> Result<Outcome, IpsecError> {
        let (reply, outcome) = oneshot::channel();
        let job = Job {
            work,
            enqueued: Instant::now(),
            reply,
            in_flight: InFlight::new(&self.in_flight),
        };
        match tokio::time::timeout(self.queue_wait, self.sender().send_async(job)).await {
            Ok(Ok(())) => {}
            Ok(Err(_disconnected)) => {
                error!("IPsec: no XFRM netlink worker is running; kernel operation not sent");
                return Err(IpsecError::Command(
                    "xfrm netlink: no worker running, not sent".to_string(),
                ));
            }
            Err(_elapsed) => {
                warn!(
                    capacity = self.capacity,
                    waited = ?self.queue_wait,
                    "IPsec: XFRM netlink queue full; kernel operation not sent"
                );
                return Err(IpsecError::Command(format!(
                    "xfrm netlink: queue full ({} jobs) for {:?}, not sent",
                    self.capacity, self.queue_wait
                )));
            }
        }
        outcome.await.map_err(|_| {
            IpsecError::Command("xfrm netlink: the worker stopped before answering".to_string())
        })
    }

    /// Jobs made and not yet answered or dropped.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Jobs waiting in the queue for a worker.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.queue.get().map_or(0, flume::Sender::len)
    }
}

/// A worker: take jobs until every sender is gone.
fn run(
    index: usize,
    queue: &flume::Receiver<Job>,
    connect: &Arc<Connect>,
    ack_timeout: Duration,
    queue_wait: Duration,
) {
    let mut transport: Option<Box<dyn XfrmTransport>> = None;
    let mut sequence: u32 = 0;
    let mut buffer = vec![0u8; RECV_BUFFER];
    while let Ok(job) = queue.recv() {
        let Job {
            work,
            enqueued,
            reply,
            in_flight,
        } = job;
        let waited = enqueued.elapsed();
        let outcome = if waited > queue_wait {
            warn!(
                worker = index,
                ?waited,
                "IPsec: XFRM netlink job waited too long in the queue; not sent"
            );
            refuse(&work, || {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("waited {waited:?} in the queue, not sent"),
                )
            })
        } else {
            match ensure_transport(&mut transport, connect) {
                Err(open_error) => {
                    error!(worker = index, %open_error, "IPsec: could not open the XFRM netlink socket");
                    let kind = open_error.kind();
                    let text = open_error.to_string();
                    refuse(&work, || io::Error::new(kind, format!("socket: {text}")))
                }
                Ok(socket) => {
                    let mut exchange = Exchange {
                        transport: socket,
                        sequence: &mut sequence,
                        buffer: &mut buffer,
                        ack_timeout,
                        worker: index,
                        broken: false,
                    };
                    let outcome = match work {
                        Work::Acks(messages) => Outcome::Acks(exchange.acks(messages)),
                        Work::DumpSa => Outcome::Dump(exchange.dump()),
                    };
                    if exchange.broken {
                        // Opened again for the next job.
                        transport = None;
                    }
                    outcome
                }
            }
        };
        // Counted out before the reply, so a caller holding its reply sees it.
        drop(in_flight);
        if reply.send(outcome).is_err() {
            debug!(
                worker = index,
                "IPsec: XFRM netlink caller gone before the reply"
            );
        }
    }
}

fn ensure_transport<'a>(
    transport: &'a mut Option<Box<dyn XfrmTransport>>,
    connect: &Arc<Connect>,
) -> io::Result<&'a mut Box<dyn XfrmTransport>> {
    if transport.is_none() {
        *transport = Some(connect()?);
    }
    transport
        .as_mut()
        .ok_or_else(|| io::Error::other("netlink: no socket"))
}

/// The same error for every message of a job that was not sent.
fn refuse(work: &Work, error: impl Fn() -> io::Error) -> Outcome {
    match work {
        Work::Acks(messages) => Outcome::Acks(messages.iter().map(|_| Err(error())).collect()),
        Work::DumpSa => Outcome::Dump(Err(error())),
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// One netlink message of a received datagram.
struct Reply<'a> {
    message_type: u16,
    sequence: u32,
    body: &'a [u8],
}

/// Split a datagram into its messages; `Err` on a malformed one.
fn replies(datagram: &[u8]) -> Result<Vec<Reply<'_>>, io::Error> {
    let mut found = Vec::new();
    let mut offset = 0;
    while offset + NLMSG_HDR_LEN <= datagram.len() {
        let header = &datagram[offset..offset + NLMSG_HDR_LEN];
        let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if length < NLMSG_HDR_LEN || offset + length > datagram.len() {
            return Err(io::Error::other("netlink: malformed reply"));
        }
        found.push(Reply {
            message_type: u16::from_ne_bytes([header[4], header[5]]),
            sequence: u32::from_ne_bytes([header[8], header[9], header[10], header[11]]),
            body: &datagram[offset + NLMSG_HDR_LEN..offset + length],
        });
        offset += align_to(length, NLMSG_ALIGNTO);
    }
    Ok(found)
}

/// The errno an `NLMSG_ERROR` body carries (0 = ack).
fn errno(body: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(body.get(..4)?.try_into().ok()?))
}

fn errno_result(body: &[u8]) -> io::Result<()> {
    match errno(body) {
        Some(0) => Ok(()),
        Some(error) => Err(io::Error::from_raw_os_error(-error)),
        None => Err(io::Error::other("netlink: short NLMSG_ERROR")),
    }
}

struct Exchange<'a> {
    transport: &'a mut Box<dyn XfrmTransport>,
    sequence: &'a mut u32,
    buffer: &'a mut Vec<u8>,
    ack_timeout: Duration,
    worker: usize,
    /// The socket failed; drop it.
    broken: bool,
}

impl Exchange<'_> {
    fn next_sequence(&mut self) -> u32 {
        *self.sequence = self.sequence.wrapping_add(1);
        if *self.sequence == 0 {
            *self.sequence = 1;
        }
        *self.sequence
    }

    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let sent = self.transport.send(datagram).inspect_err(|_| {
            self.broken = true;
        })?;
        if sent != datagram.len() {
            self.broken = true;
            return Err(io::Error::other(format!(
                "netlink: short send ({sent}/{})",
                datagram.len()
            )));
        }
        Ok(())
    }

    /// Receive one datagram; `Interrupted` is retried.
    fn recv(&mut self) -> io::Result<usize> {
        loop {
            match self.transport.recv(self.buffer) {
                Ok(0) => {
                    self.broken = true;
                    return Err(io::Error::other("netlink: socket closed"));
                }
                Ok(received) => return Ok(received),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if is_timeout(&error) => return Err(error),
                Err(error) => {
                    self.broken = true;
                    return Err(error);
                }
            }
        }
    }

    fn timed_out(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no reply from the kernel within {:?}", self.ack_timeout),
        )
    }

    fn acks(&mut self, messages: Vec<Vec<u8>>) -> Vec<io::Result<()>> {
        let count = messages.len();
        let first = self.next_sequence();
        let mut datagram = Vec::with_capacity(messages.iter().map(Vec::len).sum());
        for (offset, mut message) in messages.into_iter().enumerate() {
            let sequence = if offset == 0 {
                first
            } else {
                self.next_sequence()
            };
            if message.len() >= NLMSG_HDR_LEN {
                message[8..12].copy_from_slice(&sequence.to_ne_bytes());
            }
            datagram.extend_from_slice(&message);
        }
        let mut results: Vec<Option<io::Result<()>>> = (0..count).map(|_| None).collect();
        if let Err(error) = self.send(&datagram) {
            let (kind, text) = (error.kind(), error.to_string());
            return (0..count)
                .map(|_| Err(io::Error::new(kind, text.clone())))
                .collect();
        }
        let mut open = count;
        while open > 0 {
            let received = match self.recv() {
                Ok(received) => received,
                Err(error) => {
                    if is_timeout(&error) {
                        error!(
                            worker = self.worker,
                            unanswered = open,
                            sequence = first,
                            timeout = ?self.ack_timeout,
                            "IPsec: no XFRM netlink ack from the kernel; operation failed"
                        );
                    }
                    let (kind, text) = if is_timeout(&error) {
                        let timed_out = self.timed_out();
                        (timed_out.kind(), timed_out.to_string())
                    } else {
                        (error.kind(), error.to_string())
                    };
                    for slot in results.iter_mut().filter(|slot| slot.is_none()) {
                        *slot = Some(Err(io::Error::new(kind, text.clone())));
                    }
                    break;
                }
            };
            let parsed = match replies(&self.buffer[..received]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    warn!(worker = self.worker, %error, "IPsec: malformed XFRM netlink reply dropped");
                    continue;
                }
            };
            for reply in parsed {
                let index = reply.sequence.wrapping_sub(first) as usize;
                let answer = match reply.message_type {
                    NLMSG_ERROR => errno_result(reply.body),
                    NLMSG_DONE => Ok(()),
                    _ => continue,
                };
                match results.get_mut(index) {
                    Some(slot @ None) => {
                        *slot = Some(answer);
                        open -= 1;
                    }
                    _ => debug!(
                        worker = self.worker,
                        sequence = reply.sequence,
                        "IPsec: stale XFRM netlink reply dropped"
                    ),
                }
            }
        }
        results
            .into_iter()
            .map(|slot| slot.unwrap_or_else(|| Err(io::Error::other("netlink: no reply"))))
            .collect()
    }

    fn dump(&mut self) -> io::Result<HashMap<u32, u64>> {
        let sequence = self.next_sequence();
        // Header-only GETSA dump request: no XFRMA_ADDRESS_FILTER attribute,
        // so the kernel dumps every SA.
        let mut request = Vec::with_capacity(NLMSG_HDR_LEN);
        request.extend_from_slice(&(NLMSG_HDR_LEN as u32).to_ne_bytes());
        request.extend_from_slice(&XFRM_MSG_GETSA.to_ne_bytes());
        request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&sequence.to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes()); // pid (kernel fills in)
        self.send(&request)?;

        let mut use_times = HashMap::new();
        loop {
            let received = match self.recv() {
                Ok(received) => received,
                Err(error) if is_timeout(&error) => {
                    error!(
                        worker = self.worker,
                        sequence,
                        timeout = ?self.ack_timeout,
                        "IPsec: XFRM SA dump did not finish; dump failed"
                    );
                    return Err(self.timed_out());
                }
                Err(error) => return Err(error),
            };
            for reply in replies(&self.buffer[..received])? {
                if reply.sequence != sequence {
                    debug!(
                        worker = self.worker,
                        sequence = reply.sequence,
                        "IPsec: stale XFRM netlink reply dropped"
                    );
                    continue;
                }
                match reply.message_type {
                    NLMSG_DONE => return Ok(use_times),
                    // errno 0 terminates the dump too.
                    NLMSG_ERROR => return errno_result(reply.body).map(|()| use_times),
                    XFRM_MSG_NEWSA => {
                        if let Some((spi, last_active)) = parse_sa_use_time(reply.body) {
                            use_times.insert(spi, last_active);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
