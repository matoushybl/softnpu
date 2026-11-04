// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Standalone SoftNPU userspace datapath.
//!
//! This is the non-propolis ("sidecar_softnpu" zone) implementation. Unlike
//! the previous revision it does *not* use the async `dlpi::recv_async` path
//! (which registered a fresh `tokio::io::unix::AsyncFd` with the reactor for
//! every single packet, and only ever pulled one packet per wakeup). Each
//! port direction runs on its own OS thread over raw STREAMS I/O: a single
//! blocking `poll(2)` per idle edge, then a drain of everything already
//! queued with non-blocking `getmsg(2)` (one syscall per frame, never a
//! poll-per-recv), reusing all per-packet buffers.
//!
//! Receive and transmit are *decoupled*: each DLPI handle has a dedicated
//! transmit thread fed by a fixed-slot SPSC ring. The receive threads only
//! recv, process through the pipeline, and push the resulting frame into a
//! pre-allocated ring slot; they never block on `putmsg(2)`. This is
//! important because the DLPI transmit (`putmsg(2)`) can be
//! expensive/blocking, and doing it inline in the receive loop serialises
//! rx and tx and collapses the datapath throughput. Under sustained
//! back-to-back traffic the ring performs no wake syscalls and no
//! allocation at all; condvar wakes only happen at idle and backpressure
//! transitions.
//!
//! The management UDS protocol and the P4 program semantics are unchanged.
//!
//! Each DLPI stream also gets the STREAMS buffer module (bufmod(4D)) pushed
//! on it: dld's raw-mode receive drops frames silently whenever the
//! stream-head read queue is over its default hiwat (STRHIGH = 5120 bytes),
//! which bursts of a few back-to-back frames exceed. bufmod moves dld's
//! flow-control gate off the stream head, raises the head hiwat on
//! configuration, and frames buffered messages with per-frame sb_hdr
//! records the receive loop parses back out.

use anyhow::{anyhow, Result};
use clap::Parser;
use dlpi::DlpiHandle;
use libloading::os::unix::{Library, Symbol, RTLD_NOW};
use slog::{debug, error, info, warn, Drain, Logger};
use softnpu::p4rs::{packet_in, packet_out, Pipeline};
use softnpu_client::cli::get_styles;
use softnpu_client::config::{Config, Port};
use std::cell::UnsafeCell;
use std::fs::read_to_string;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::UnixDatagram;

/// Ethernet header (14) + sidecar header (24). Buffers must have at least this
/// much headroom so a full-MTU frame can be re-framed with a sidecar header.
const L2_HEADROOM: usize = 14 + 24;
const ETH_HDR_LEN: usize = 14;
const SIDECAR_HDR_LEN: usize = 24;
/// Offset of the encapsulated packet's L3 data in a sidecar-framed packet.
const L3_OFFSET: usize = ETH_HDR_LEN + SIDECAR_HDR_LEN;
/// Ring slots per transmit direction. Slots are pre-allocated at largest-frame
/// capacity; 256 slots is ~2.5 MB per ring at 9600-byte frames and covers an
/// entire stream-head hiwat worth of burst.
const TX_QUEUE_DEPTH: usize = 256;

/// STREAMS ioctls (sys/stropts.h); STR = 'S' << 8.
const I_PUSH: libc::c_int = 0x5302; // STR|02
const I_POP: libc::c_int = 0x5301; // STR|01
const I_STR: libc::c_int = 0x5308; // STR|010

/// bufmod ioctls (sys/bufmod.h); SBIOC = 'B' << 8.
const SBIOCSTIME: libc::c_int = 0x4201;
const SBIOCSCHUNK: libc::c_int = 0x4204;
const SBIOCSFLAGS: libc::c_int = 0x4208;

/// bufmod buffering modes (sys/bufmod.h).
const SB_NO_PROTO_CVT: u32 = 0x4;
const SB_DEFER_CHUNK: u32 = 0x8;
const SB_NO_DROPS: u32 = 0x10;

/// Per-frame record bufmod prepends in every chunk:
/// u32 origlen, u32 msglen, u32 totlen, u32 drops, struct timeval32 stamp.
const SB_HDR_LEN: usize = 24;
/// bufmod pads each record to a multiple of sizeof (ulong_t).
const SB_ALIGN: usize = 8;

/// Default bufmod chunk size. The stream-head read-queue acceptance budget
/// becomes 4*chunk+512 bytes (bufmod M_SETOPTS SNIT_HIWAT): ~344 frames of
/// 1526B at the default, versus ~4 frames unbuffered.
const BUFMOD_CHUNK_DEFAULT: usize = 131072;

/// STREAMS `struct strioctl` (sys/stropts.h) for I_STR.
#[repr(C)]
struct StrIoctl {
    ic_cmd: libc::c_int,
    ic_timout: libc::c_int,
    ic_len: libc::c_int,
    ic_dp: *mut libc::c_char,
}

/// Native `struct timeval` (sys/time.h) for SBIOCSTIME.
#[repr(C)]
struct Timeval {
    tv_sec: libc::time_t,
    tv_usec: libc::suseconds_t,
}

/// bufmod configuration for every DLPI stream, resolved once from the
/// environment so racks can be re-tuned without rebuilding.
#[derive(Clone, Copy)]
struct BufmodCfg {
    enabled: bool,
    /// Maximum bytes accumulated per chunk before it is pushed to the
    /// stream head. Must stay at or above the largest raw frame.
    chunk: usize,
    /// Flush interval for partial chunks, in ticks (10ms each at hz=100).
    ticks: i64,
}

impl BufmodCfg {
    fn from_env() -> Self {
        let enabled = match std::env::var("SOFTNPU_NO_BUFMOD") {
            Ok(v) => v.is_empty() || v == "0",
            Err(_) => true,
        };
        let chunk = std::env::var("SOFTNPU_BUFMOD_CHUNK")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(BUFMOD_CHUNK_DEFAULT)
            .clamp(16384, 1 << 20);
        let ticks = std::env::var("SOFTNPU_BUFMOD_TICKS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(1)
            .clamp(1, 60);
        BufmodCfg {
            enabled,
            chunk,
            ticks,
        }
    }

    /// Receive buffer size able to hold the largest possible chunk blob:
    /// a full chunk plus the final (possibly oversized) record.
    fn recv_buf(&self, mtu: usize) -> usize {
        self.chunk + mtu + L2_HEADROOM + SB_HDR_LEN + SB_ALIGN + 64
    }
}

#[derive(Clone)]
pub struct Switch {
    pub ports: Vec<SwitchPort>,
}

#[derive(Clone, Copy)]
pub struct SwitchPort {
    pub sidecar: DlpiHandle,
    pub scrimlet: DlpiHandle,
    pub mtu: usize,
    /// Whether bufmod was successfully pushed on each stream.
    pub sidecar_bufmod: bool,
    pub scrimlet_bufmod: bool,
}

/// Per-direction transmit rings. `sidecar[i]` feeds `ports[i].sidecar`,
/// `scrimlet[i]` feeds `ports[i].scrimlet`.
#[derive(Clone)]
struct TxQueues {
    sidecar: Vec<Arc<TxRing>>,
    scrimlet: Vec<Arc<TxRing>>,
}

impl Switch {
    fn new(
        ports: &Vec<Port>,
        bufmod: &BufmodCfg,
        log: &Logger,
    ) -> Result<Switch> {
        Ok(Switch {
            ports: Self::init_ports(ports, bufmod, log)?,
        })
    }

    fn init_ports(
        ports: &Vec<Port>,
        bufmod: &BufmodCfg,
        log: &Logger,
    ) -> Result<Vec<SwitchPort>> {
        let mut result = Vec::new();
        for p in ports {
            let (sidecar, sidecar_bufmod) =
                Self::init_port(&p.sidecar, bufmod, log).map_err(|e| {
                    anyhow!(
                        "initializing sidecar port {} failed: {}",
                        p.sidecar,
                        e,
                    )
                })?;
            let (scrimlet, scrimlet_bufmod) =
                Self::init_port(&p.scrimlet, bufmod, log).map_err(|e| {
                    anyhow!(
                        "initializing scrimlet port {} failed: {}",
                        p.sidecar,
                        e,
                    )
                })?;
            result.push(SwitchPort {
                sidecar,
                scrimlet,
                mtu: p.mtu,
                sidecar_bufmod,
                scrimlet_bufmod,
            })
        }
        Ok(result)
    }

    fn init_port(
        devname: &str,
        bufmod: &BufmodCfg,
        log: &Logger,
    ) -> Result<(DlpiHandle, bool)> {
        let p = dlpi::open(devname, dlpi::sys::DLPI_RAW)?;
        dlpi::bind(p, 0x86dd)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_MULTI)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_SAP)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_PHYS)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_RX_ONLY)?;
        let active = if bufmod.enabled {
            push_bufmod(p, bufmod, devname, log)
        } else {
            false
        };
        Ok((p, active))
    }
}

/// Lightweight, always-on datapath counters. Reported every few seconds so the
/// bottleneck (blocked on rx vs. time in the pipeline vs. time in tx) is
/// directly observable.
#[derive(Default)]
struct Stats {
    rx_pkts: AtomicU64,
    rx_bytes: AtomicU64,
    tx_pkts: AtomicU64,
    rx_err: AtomicU64,
    /// TX queue send failures (queue disconnected).
    tx_dropped: AtomicU64,
    /// Raw getmsg returns while bufmod framing is active.
    rx_chunks: AtomicU64,
    /// Frames dropped by bufmod per the last sb_hdr.drops seen (0 while
    /// SB_NO_DROPS holds).
    bufmod_drops: AtomicU64,
    /// Number of times the blocking recv returned (one "wakeup").
    wakeups: AtomicU64,
    /// Additional packets pulled in the non-blocking drain after the wakeup.
    drained: AtomicU64,
    /// Batches where more than one packet was available.
    multi_batches: AtomicU64,
    process_ns: AtomicU64,
    send_ns: AtomicU64,
    block_ns: AtomicU64,
    lock_ns: AtomicU64,
    handle_ns: AtomicU64,
    recv_ns: AtomicU64,
}

impl Stats {
    fn snapshot(&self) -> [u64; 15] {
        [
            self.rx_pkts.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_pkts.load(Ordering::Relaxed),
            self.rx_err.load(Ordering::Relaxed),
            self.wakeups.load(Ordering::Relaxed),
            self.drained.load(Ordering::Relaxed),
            self.multi_batches.load(Ordering::Relaxed),
            self.process_ns.load(Ordering::Relaxed),
            self.send_ns.load(Ordering::Relaxed),
            self.lock_ns.load(Ordering::Relaxed),
            self.handle_ns.load(Ordering::Relaxed),
            self.recv_ns.load(Ordering::Relaxed),
            self.tx_dropped.load(Ordering::Relaxed),
            self.rx_chunks.load(Ordering::Relaxed),
            self.bufmod_drops.load(Ordering::Relaxed),
        ]
    }
}

fn str_ioctl(
    fd: libc::c_int,
    cmd: libc::c_int,
    dp: *mut libc::c_char,
    len: libc::c_int,
) -> std::io::Result<()> {
    let sic = StrIoctl {
        ic_cmd: cmd,
        ic_timout: 15,
        ic_len: len,
        ic_dp: dp,
    };
    let ret = unsafe {
        libc::ioctl(fd, I_STR, &sic as *const StrIoctl as *mut libc::c_void)
    };
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Push and configure bufmod(4D) on a raw DLPI stream. See the header
/// docs; on any failure pop the module and return false so the stream
/// keeps running unbuffered rather than half-buffered (bufmod defaults
/// would batch frames with no flush timeout).
fn push_bufmod(
    dh: DlpiHandle,
    cfg: &BufmodCfg,
    devname: &str,
    log: &Logger,
) -> bool {
    let fd = unsafe { dlpi::sys::dlpi_fd(dh.0) };
    if fd < 0 {
        warn!(log, "bufmod: {}: no fd; running unbuffered", devname);
        return false;
    }
    let mut chunk: u32 = cfg.chunk as u32;
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: cfg.ticks * 10_000,
    };
    let mut flags: u32 = SB_NO_PROTO_CVT | SB_DEFER_CHUNK | SB_NO_DROPS;
    let ok = unsafe {
        libc::ioctl(fd, I_PUSH, b"bufmod\0".as_ptr() as *const libc::c_char)
            == 0
            && str_ioctl(
                fd,
                SBIOCSCHUNK,
                &mut chunk as *mut u32 as *mut libc::c_char,
                std::mem::size_of::<u32>() as libc::c_int,
            )
            .is_ok()
            && str_ioctl(
                fd,
                SBIOCSTIME,
                &mut tv as *mut Timeval as *mut libc::c_char,
                std::mem::size_of::<Timeval>() as libc::c_int,
            )
            .is_ok()
            && str_ioctl(
                fd,
                SBIOCSFLAGS,
                &mut flags as *mut u32 as *mut libc::c_char,
                std::mem::size_of::<u32>() as libc::c_int,
            )
            .is_ok()
    };
    if !ok {
        let e = std::io::Error::last_os_error();
        warn!(log, "bufmod: {}: {}; running unbuffered", devname, e);
        let _ = unsafe {
            libc::ioctl(fd, I_POP, std::ptr::null_mut::<libc::c_void>())
        };
        return false;
    }
    info!(
        log,
        "bufmod: {}: chunk {}B ticks {} (stream-head acceptance ~{}B)",
        devname,
        cfg.chunk,
        cfg.ticks,
        4 * cfg.chunk + 512
    );
    true
}

// ---------------------------------------------------------------------------
// Phase-1 syscall surgery: raw STREAMS I/O + SPSC transmit rings.
//
// The shipped path pays, per packet: a poll(0) inside every drain recv
// (libdlpi wraps each getmsg in a poll), a sync_channel wake/park pair plus
// a Vec allocation on the tx handoff, and several clock_gettime calls for
// per-packet timing. Under sustained back-to-back load the ring below
// performs no wake syscalls and no allocation at all, and a receive burst
// costs one getmsg per frame and a single blocking poll per idle edge.
// ---------------------------------------------------------------------------

/// STREAMS `struct strbuf` (sys/stropts.h).
#[repr(C)]
struct StrBuf {
    maxlen: libc::c_int,
    len: libc::c_int,
    buf: *mut libc::c_char,
}

/// `struct pollfd` (poll.h); only used on the idle edge.
#[repr(C)]
struct PollFd {
    fd: libc::c_int,
    events: libc::c_short,
    revents: libc::c_short,
}

extern "C" {
    fn getmsg(
        fd: libc::c_int,
        ctlp: *mut StrBuf,
        datap: *mut StrBuf,
        flagsp: *mut libc::c_int,
    ) -> libc::c_int;
    fn putmsg(
        fd: libc::c_int,
        ctlp: *const StrBuf,
        datap: *const StrBuf,
        flags: libc::c_int,
    ) -> libc::c_int;
    fn poll(
        fds: *mut PollFd,
        nfds: libc::c_ulong,
        timeout: libc::c_int,
    ) -> libc::c_int;
}

const POLLIN: libc::c_short = 0x0001;
/// getmsg flag bits: a part did not fit in its buffer.
const MORECTL: libc::c_int = 0x0001;
const MOREDATA: libc::c_int = 0x0002;

/// Raw fd of a DLPI handle (same libdlpi accessor the bufmod code uses).
fn dlpi_raw_fd(dh: DlpiHandle) -> libc::c_int {
    unsafe { dlpi::sys::dlpi_fd(dh.0) }
}

/// Per-packet timing is off by default: every sample is a clock_gettime
/// syscall on the hot path. SOFTNPU_NANO=1 re-enables the ns-accurate STATS
/// breakdowns (avg_lock_us, avg_process_us, ...).
static NANO: AtomicBool = AtomicBool::new(false);

fn nano() -> bool {
    NANO.load(Ordering::Relaxed)
}

fn set_flags_nonblocking(fd: libc::c_int) -> std::io::Result<()> {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl == -1
            || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == -1
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// One raw getmsg against a (non-blocking) DLPI stream head. Returns the
/// data length, or WouldBlock when no message is queued.
fn raw_getmsg(
    fd: libc::c_int,
    ctl: &mut [u8],
    data: &mut [u8],
) -> std::io::Result<usize> {
    let mut ctlbuf = StrBuf {
        maxlen: ctl.len() as libc::c_int,
        len: 0,
        buf: ctl.as_mut_ptr() as *mut libc::c_char,
    };
    let mut databuf = StrBuf {
        maxlen: data.len() as libc::c_int,
        len: 0,
        buf: data.as_mut_ptr() as *mut libc::c_char,
    };
    let mut flags: libc::c_int = 0;
    let ret = unsafe { getmsg(fd, &mut ctlbuf, &mut databuf, &mut flags) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if (flags & (MORECTL | MOREDATA)) != 0 {
        // Cannot happen for DLIOCRAW frames with these buffer sizes. Treat
        // as an RX error rather than corrupt a frame.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "getmsg: truncated part",
        ));
    }
    Ok(databuf.len as usize)
}

/// putmsg on the raw transmit stream (data part only). EAGAIN (write side
/// full under O_NONBLOCK) is retried briefly with 100 us parks.
fn raw_putmsg(fd: libc::c_int, bytes: &[u8]) -> std::io::Result<()> {
    let databuf = StrBuf {
        maxlen: bytes.len() as libc::c_int,
        len: bytes.len() as libc::c_int,
        buf: bytes.as_ptr() as *mut libc::c_char,
    };
    let mut spins = 0u32;
    loop {
        let ret = unsafe { putmsg(fd, ptr::null(), &databuf, 0) };
        if ret == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EAGAIN) && spins < 4096 {
            spins += 1;
            std::thread::park_timeout(Duration::from_micros(100));
            continue;
        }
        return Err(e);
    }
}

/// Block on the receive fd until a frame may be queued.
fn raw_poll_in(fd: libc::c_int) -> std::io::Result<()> {
    let mut pfd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    let ret = unsafe { poll(&mut pfd, 1, -1) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Fixed-slot single-producer / single-consumer ring between a receive
/// thread and one transmit handle. The producer pushes whole frames into
/// pre-allocated slots (no allocation on the hot path); the consumer
/// putmsg's them off the receive path. Wake/sleep syscalls only happen at
/// idle and backpressure edges, never per-packet in steady flow.
struct TxRing {
    slots: Box<[UnsafeCell<Vec<u8>>]>,
    mask: u64,
    head: AtomicU64,
    tail: AtomicU64,
    /// TX thread is (about to be) parked; producer must condvar-notify.
    tx_idle: AtomicBool,
    tx_lk: Mutex<()>,
    tx_cv: Condvar,
    /// Producer is (about to be) blocked on a full ring; consumer notifies.
    full: AtomicBool,
    room_lk: Mutex<()>,
    room_cv: Condvar,
    /// Serializes producers for the whole push (including any back-pressure
    /// wait). Any pipeline thread may target any port's ring
    /// (`send_to_ext_port` / `send_to_cpu_port`), so these rings are
    /// genuinely multi-producer: without this lock two producers can claim
    /// the same slot (torn frame, lost head increment) and, worse, park two
    /// waiters on `room_cv`, which breaks the single-waiter assumption of the
    /// `full` flag + `notify_one` pair -- the stranded-waiter wedge seen live
    /// ~17:00 on port 1 under a sustained egress burst. Uncontended in the
    /// common case (one producer active per ring at a time).
    push_lk: Mutex<()>,
}

// Safety: the single producer thread holds exclusive `&mut` access to
// slots in [head, head + len), the single consumer thread to the one slot
// at `tail`; the strict `h - t < len` bound keeps those ranges disjoint.
unsafe impl Sync for TxRing {}

impl TxRing {
    fn new(depth: usize, frame_max: usize) -> TxRing {
        assert!(depth.is_power_of_two());
        let slots = (0..depth)
            .map(|_| UnsafeCell::new(Vec::with_capacity(frame_max)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        TxRing {
            slots,
            mask: (depth as u64) - 1,
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            tx_idle: AtomicBool::new(true),
            tx_lk: Mutex::new(()),
            tx_cv: Condvar::new(),
            full: AtomicBool::new(false),
            room_lk: Mutex::new(()),
            room_cv: Condvar::new(),
            push_lk: Mutex::new(()),
        }
    }

    fn len(&self) -> u64 {
        self.slots.len() as u64
    }

    /// Producer side (pipeline thread). Backpressures when the ring is
    /// full, preserving the old blocking-send behaviour: the frame is always
    /// delivered once room appears, never dropped.
    fn push(&self, bytes: &[u8]) {
        // Hold the producer lock across the entire operation, waits included:
        // (a) slot write + head publish must be atomic w.r.t. other producers
        //     (multi-producer rings), and
        // (b) at most one waiter may ever sit on `room_cv`, which is what
        //     makes the `full` flag + `notify_one` pairing in `tx_drain`
        //     correct.
        let _p = self.push_lk.lock().unwrap();
        loop {
            let h = self.head.load(Ordering::Relaxed);
            let t = self.tail.load(Ordering::Acquire);
            if h.wrapping_sub(t) < self.len() {
                let slot =
                    unsafe { &mut *self.slots[(h & self.mask) as usize].get() };
                slot.clear();
                slot.extend_from_slice(bytes);
                self.head.store(h.wrapping_add(1), Ordering::Release);
                if self.tx_idle.swap(false, Ordering::AcqRel) {
                    // The idle mutex must be held across the clear and the
                    // notify: otherwise the notification can land between
                    // the consumer's final head re-check and its condvar
                    // entry and be lost, deadlocking both sides (seen live
                    // ~15 min into a converged rack). Held only on the
                    // idle -> busy transition, never per-packet.
                    let _g = self.tx_lk.lock().unwrap();
                    self.tx_cv.notify_one();
                }
                return;
            }
            // Full: wait for the tx thread to make room, then retry the push
            // from the top. (An earlier revision `return`ed here, silently
            // dropping every frame that hit the back-pressure edge.)
            let mut g = self.room_lk.lock().unwrap();
            loop {
                let h = self.head.load(Ordering::Relaxed);
                let t = self.tail.load(Ordering::Acquire);
                if h.wrapping_sub(t) < self.len() {
                    break;
                }
                self.full.store(true, Ordering::Release);
                g = self.room_cv.wait(g).unwrap();
            }
            drop(g);
        }
    }

    /// Consumer side (tx thread): drain the ring to the DLPI stream.
    fn tx_drain(
        &self,
        fd: libc::c_int,
        stats: Arc<Stats>,
        log: Logger,
        index: usize,
        dir: &'static str,
    ) {
        info!(log, "tx handler running for {} port {}", dir, index);
        loop {
            let t = self.tail.load(Ordering::Relaxed);
            let h = self.head.load(Ordering::Acquire);
            if t == h {
                // Idle: park. A producer that pushed after our idle-store
                // sees the flag, and submits its notification while holding
                // this same mutex -- so the notify either reaches us while
                // parked, or our re-check (still under the lock) sees the
                // head advance and we never sleep. No lost-wake window.
                let g = self.tx_lk.lock().unwrap();
                self.tx_idle.store(true, Ordering::Release);
                let h2 = self.head.load(Ordering::Acquire);
                if h2 == t {
                    let _g = self.tx_cv.wait(g).unwrap();
                }
                continue;
            }
            let slot = unsafe { &*self.slots[(t & self.mask) as usize].get() };
            let t0 = if nano() { Some(Instant::now()) } else { None };
            match raw_putmsg(fd, slot.as_slice()) {
                Ok(()) => {
                    stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                    error!(log, "tx ({},{}): {}", dir, index, e);
                }
            }
            if let Some(t0) = t0 {
                stats.send_ns.fetch_add(
                    t0.elapsed().as_nanos() as u64,
                    Ordering::Relaxed,
                );
            }
            self.tail.store(t.wrapping_add(1), Ordering::Release);
            // Mirror of the idle edge: the flag clear and the notify must
            // both happen under `room_lk`, the mutex the blocked producer
            // holds across its final tail re-check and `full.store(true)`.
            // Clearing the flag outside the lock can land in that window,
            // skip the notify, and leave the producer asleep on `room_cv`
            // with room actually available -- a permanent wedge. Uncontended
            // in practice (the producer only takes `room_lk` on
            // back-pressure) and negligible beside the putmsg syscall it
            // already sits behind.
            {
                let _g = self.room_lk.lock().unwrap();
                if self.full.swap(false, Ordering::AcqRel) {
                    self.room_cv.notify_one();
                }
            }
        }
    }
}

/// Deliver one stream-head message: either a bare frame (bufmod off, or
/// SB_DEFER_CHUNK's first-frame fast pass) or a bufmod chunk holding
/// several [sb_hdr (24B, padded)] records. A message is treated as a
/// chunk only when it *validates* as one end-to-end: records tile the
/// message exactly with inter-locked lengths, a check an Ethernet frame
/// cannot trip in practice.
fn deliver_msg<F>(
    data: &[u8],
    bufmod: bool,
    mod_drops: &mut u32,
    stats: &Stats,
    handle: &mut F,
) -> u64
where
    F: FnMut(&[u8]),
{
    if !bufmod {
        stats
            .rx_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        handle(data);
        return 1;
    }

    let word = |off: usize| -> u32 {
        u32::from_ne_bytes(data[off..off + 4].try_into().unwrap())
    };

    // Pass 1: validate the entire message as a sequence of records.
    let mut end = 0usize;
    let mut drops = *mod_drops;
    while end < data.len() {
        let rem = data.len() - end;
        if rem < SB_HDR_LEN {
            end = usize::MAX;
            break;
        }
        let origlen = word(end) as usize;
        let msglen = word(end + 4) as usize;
        let totlen = word(end + 8) as usize;
        if msglen > origlen
            || totlen != (SB_HDR_LEN + msglen + SB_ALIGN - 1) & !(SB_ALIGN - 1)
            || totlen > rem
        {
            end = usize::MAX;
            break;
        }
        drops = word(end + 12);
        end += totlen;
    }

    if end != data.len() {
        // Not a chunk: bare frame (SB_DEFER_CHUNK fast pass).
        stats
            .rx_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        handle(data);
        return 1;
    }

    // Pass 2: deliver each record's payload.
    let mut off = 0usize;
    let mut frames = 0u64;
    while off < end {
        let msglen = word(off + 4) as usize;
        let totlen = word(off + 8) as usize;
        handle(&data[off + SB_HDR_LEN..off + SB_HDR_LEN + msglen]);
        stats.rx_bytes.fetch_add(msglen as u64, Ordering::Relaxed);
        frames += 1;
        off += totlen;
    }
    // sb_hdr.drops is cumulative for the stream; surface any growth.
    let delta = drops.saturating_sub(*mod_drops);
    if delta > 0 {
        stats
            .bufmod_drops
            .fetch_add(delta as u64, Ordering::Relaxed);
        *mod_drops = drops;
    }
    frames
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = get_styles())]
struct Cli {
    /// soft-npu configuration file path
    config: String,

    /// UDS socket path
    #[arg(long, default_value = "/stuff")]
    uds_path: String,
}

fn load_program(
    path: &str,
    radix: u16,
) -> Result<(Library, Box<dyn Pipeline>)> {
    let lib = match unsafe { Library::open(Some(&path), RTLD_NOW) } {
        Ok(l) => l,
        Err(e) => return Err(anyhow!("failed to load p4 program: {}", e)),
    };
    let func: Symbol<unsafe extern "C" fn(u16) -> *mut dyn Pipeline> =
        match unsafe { lib.get(b"_main_pipeline_create") } {
            Ok(f) => f,
            Err(e) => {
                return Err(anyhow!(
                    "failed to load _main_pipeline_create func: {}",
                    e
                ))
            }
        };

    let boxpipe = unsafe { Box::from_raw(func(radix)) };
    Ok((lib, boxpipe))
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x2000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}

/// Ingress: packets arriving on a port's `sidecar` interface, entering the
/// switch from the sled/host side.
fn process_ingress_packet(
    index: usize,
    data: &[u8],
    switch: &Switch,
    txq: &TxQueues,
    pipeline: &Mutex<Box<dyn Pipeline>>,
    scratch: &mut Vec<u8>,
    stats: &Stats,
    log: &Logger,
) {
    let mut pkt = packet_in::new(data);

    let l0 = if nano() { Some(Instant::now()) } else { None };
    let mut pl = pipeline.lock().unwrap();
    if let Some(l0) = l0 {
        stats
            .lock_ns
            .fetch_add(l0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    let p0 = if nano() { Some(Instant::now()) } else { None };
    let output = pl.process_packet((index + 1) as u16, &mut pkt);
    if let Some(p0) = p0 {
        stats
            .process_ns
            .fetch_add(p0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    drop(pl);

    for (out_pkt, port) in output {
        if port == 0 {
            send_to_cpu_port(out_pkt, switch, txq, scratch, stats, log);
        } else {
            send_to_ext_port(out_pkt, switch, txq, port, scratch, stats, log);
        }
    }
}

/// Egress: packets arriving on a port's `scrimlet` interface. These are framed
/// with a sidecar header by the switch before being handed to the pipeline.
fn process_egress_packet(
    index: usize,
    data: &[u8],
    frame: &mut [u8],
    switch: &Switch,
    txq: &TxQueues,
    pipeline: &Mutex<Box<dyn Pipeline>>,
    scratch: &mut Vec<u8>,
    stats: &Stats,
    log: &Logger,
) {
    let n = data.len();
    if n < ETH_HDR_LEN {
        stats.rx_err.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let m = n + SIDECAR_HDR_LEN;
    if m > frame.len() {
        stats.rx_err.fetch_add(1, Ordering::Relaxed);
        error!(
            log,
            "egress frame too large for port {}: {} > {}",
            index,
            m,
            frame.len(),
        );
        return;
    }

    // Zero the header region we are about to synthesize (the original code
    // used a freshly zeroed buffer every packet), then preserve the original
    // ethertype and write the sidecar header.
    frame[..L3_OFFSET].fill(0);
    frame[..ETH_HDR_LEN].copy_from_slice(&data[..ETH_HDR_LEN]);
    let orig_ethertype = [frame[12], frame[13]];
    frame[12] = 0x09;
    frame[13] = 0x01;
    let portnum = (index as u16 + 1).to_be_bytes();
    frame[14] = 0; // sc_code = forward from userspace
    frame[15] = 0; // pad
    frame[16] = portnum[0];
    frame[17] = portnum[1];
    frame[18] = portnum[0];
    frame[19] = portnum[1];
    frame[20] = orig_ethertype[0];
    frame[21] = orig_ethertype[1];
    frame[L3_OFFSET..m].copy_from_slice(&data[ETH_HDR_LEN..n]);

    let mut pkt = packet_in::new(&frame[..m]);
    let l0 = if nano() { Some(Instant::now()) } else { None };
    let mut pl = pipeline.lock().unwrap();
    if let Some(l0) = l0 {
        stats
            .lock_ns
            .fetch_add(l0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    let p0 = if nano() { Some(Instant::now()) } else { None };
    let output = pl.process_packet((index + 1) as u16, &mut pkt);
    if let Some(p0) = p0 {
        stats
            .process_ns
            .fetch_add(p0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    drop(pl);

    for (out_pkt, port) in output {
        if port == 0 {
            debug!(
                log,
                "egress port=0 for internal packet on index {index}, dropping"
            );
            continue;
        }
        send_to_ext_port(out_pkt, switch, txq, port, scratch, stats, log);
    }
}

fn send_to_ext_port(
    pkt: packet_out<'_>,
    switch: &Switch,
    txq: &TxQueues,
    port: u16,
    scratch: &mut Vec<u8>,
    _stats: &Stats,
    log: &Logger,
) {
    let Some((idx, sp)) = (port as usize)
        .checked_sub(1)
        .and_then(|i| switch.ports.get(i).map(|sp| (i, sp)))
    else {
        warn!(
            log,
            "egress port {port} out of range (1..={}), dropping",
            switch.ports.len(),
        );
        return;
    };
    let dh = sp.sidecar;

    //TODO avoid copying the whole packet
    let mut out = pkt.header_data.clone();
    out.extend_from_slice(pkt.payload_data);

    match dlpi::send(dh, &[], out.as_slice(), None) {
        Ok(_) => {}
        Err(e) => {
            error!(log, "tx (ext,0): {}", e);
        }
    }

    // Hand the frame to the destination port's transmit ring. The receive
    // thread never performs the (potentially blocking) send itself; the
    // pre-allocated ring slot means no allocation on the hot path.
    scratch.clear();
    scratch.extend_from_slice(&pkt.header_data);
    scratch.extend_from_slice(pkt.payload_data);
    txq.sidecar[idx - 1].push(scratch);
}

fn send_to_cpu_port(
    pkt: packet_out<'_>,
    switch: &Switch,
    txq: &TxQueues,
    scratch: &mut Vec<u8>,
    _stats: &Stats,
    log: &Logger,
) {
    // get the destination port
    // 16 =
    //   size_of(ethernet) = 14 +
    //   offset(sidecar.sc_egress) = 2
    if pkt.header_data.len() < 18 {
        warn!(log, "cpu port packet too short, dropping");
        return;
    }
    let portnum =
        u16::from_be_bytes([pkt.header_data[16], pkt.header_data[17]]) as usize;

    if portnum == 0 {
        warn!(log, "got sidecar egress port of 0");
        warn!(log, "this is probably a p4 program bug");
        warn!(log, "dropping packet");
        return;
    }

    if portnum > switch.ports.len() {
        warn!(
            log,
            "portnum too large, {} of {}",
            portnum - 1,
            switch.ports.len() - 1
        );
        return;
    }

    // replace sidecar ethertype with encapsulated packet ethertype
    let et0 = pkt.header_data[20];
    let et1 = pkt.header_data[21];

    // build eth + L3 + payload without mutating the pipeline's output
    scratch.clear();
    scratch.extend_from_slice(&pkt.header_data[..12]);
    scratch.push(et0);
    scratch.push(et1);
    // skip sidecar header and write out L3 header
    scratch.extend_from_slice(&pkt.header_data[L3_OFFSET..]);
    scratch.extend_from_slice(pkt.payload_data);
    txq.scrimlet[portnum - 1].push(scratch);
}

/// Receive loop for one raw DLPI stream fd. Idles in a single blocking
/// poll(-1); a wakeup drains everything already queued with non-blocking
/// getmsg (one syscall per frame, no per-recv poll) before blocking again.
/// With bufmod active each getmsg may return a chunk of many frames.
fn recv_loop<F>(
    fd: libc::c_int,
    buf_len: usize,
    bufmod: bool,
    stats: Arc<Stats>,
    log: Logger,
    mut handle: F,
) where
    F: FnMut(&[u8]),
{
    let mut ctl = vec![0u8; 512];
    let mut data = vec![0u8; buf_len];
    let mut mod_drops: u32 = 0;

    loop {
        let t0 = if nano() { Some(Instant::now()) } else { None };
        let n = match raw_getmsg(fd, &mut ctl, &mut data) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Idle edge: exactly one blocking poll per wakeup.
                if let Err(e) = raw_poll_in(fd) {
                    stats.rx_err.fetch_add(1, Ordering::Relaxed);
                    error!(log, "rx poll: {}", e);
                    continue;
                }
                match raw_getmsg(fd, &mut ctl, &mut data) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Spurious wakeup; go back to the idle edge.
                        continue;
                    }
                    Err(e) => {
                        stats.rx_err.fetch_add(1, Ordering::Relaxed);
                        error!(log, "rx error: {}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                stats.rx_err.fetch_add(1, Ordering::Relaxed);
                error!(log, "rx error: {}", e);
                continue;
            }
        };
        if let Some(t0) = t0 {
            stats
                .block_ns
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        stats.wakeups.fetch_add(1, Ordering::Relaxed);
        if bufmod {
            stats.rx_chunks.fetch_add(1, Ordering::Relaxed);
        }

        let h0 = if nano() { Some(Instant::now()) } else { None };
        let frames = deliver_msg(
            &data[..n],
            bufmod,
            &mut mod_drops,
            &stats,
            &mut handle,
        );
        stats.rx_pkts.fetch_add(frames, Ordering::Relaxed);
        if let Some(h0) = h0 {
            stats
                .handle_ns
                .fetch_add(h0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }

        // Drain everything already queued without going back to the
        // scheduler: pure non-blocking getmsg, EAGAIN ends the burst.
        let mut batch = 0u64;
        loop {
            let r0 = if nano() { Some(Instant::now()) } else { None };
            let n = match raw_getmsg(fd, &mut ctl, &mut data) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    stats.rx_err.fetch_add(1, Ordering::Relaxed);
                    error!(log, "rx drain error: {}", e);
                    break;
                }
            };
            if let Some(r0) = r0 {
                stats.recv_ns.fetch_add(
                    r0.elapsed().as_nanos() as u64,
                    Ordering::Relaxed,
                );
            }
            batch += 1;
            if bufmod {
                stats.rx_chunks.fetch_add(1, Ordering::Relaxed);
            }
            let h0 = if nano() { Some(Instant::now()) } else { None };
            let frames = deliver_msg(
                &data[..n],
                bufmod,
                &mut mod_drops,
                &stats,
                &mut handle,
            );
            stats.rx_pkts.fetch_add(frames, Ordering::Relaxed);
            if let Some(h0) = h0 {
                stats.handle_ns.fetch_add(
                    h0.elapsed().as_nanos() as u64,
                    Ordering::Relaxed,
                );
            }
        }
        stats.drained.fetch_add(batch, Ordering::Relaxed);
        if batch > 0 {
            stats.multi_batches.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn spawn_reporter(stats: Arc<Stats>, log: Logger) {
    thread::spawn(move || {
        let mut last = stats.snapshot();
        loop {
            thread::sleep(Duration::from_secs(5));
            let cur = stats.snapshot();
            let d = |i: usize| cur[i] - last[i];
            let pps = d(0) as f64 / 5.0;
            let bps = d(1) as f64 / 5.0;
            let avg_proc_us = if d(0) > 0 {
                d(7) as f64 / d(0) as f64 / 1000.0
            } else {
                0.0
            };
            let avg_send_us = if d(2) > 0 {
                d(8) as f64 / d(2) as f64 / 1000.0
            } else {
                0.0
            };
            let avg_lock_us = if d(0) > 0 {
                d(9) as f64 / d(0) as f64 / 1000.0
            } else {
                0.0
            };
            let avg_handle_us = if d(0) > 0 {
                d(10) as f64 / d(0) as f64 / 1000.0
            } else {
                0.0
            };
            let avg_recv_us = if d(5) > 0 {
                d(11) as f64 / d(5) as f64 / 1000.0
            } else {
                0.0
            };
            // Use stdout directly so the numbers show up regardless of the
            // slog env-logger filter.
            println!(
                "STATS rx_pps={:.0} rx_MBps={:.2} tx_pkts={} tx_dropped={} \
                 rx_err={} wakeups={} drained={} multi_batches={} \
                 avg_lock_us={:.2} avg_process_us={:.2} \
                 avg_handle_us={:.2} avg_recv_us={:.2} avg_send_us={:.2} \
                 chunks={} bufmod_drops={}",
                pps,
                bps / 1e6,
                d(2),
                d(12),
                d(3),
                d(4),
                d(5),
                d(6),
                avg_lock_us,
                avg_proc_us,
                avg_handle_us,
                avg_recv_us,
                avg_send_us,
                d(13),
                d(14),
            );
            let _ = &log;
            last = cur;
        }
    });
}

#[tokio::main]
async fn main() {
    let log = init_logger();

    if let Err(e) = run(log.clone()).await {
        error!(log, "{}", e);
    }
}

async fn run(log: Logger) -> Result<()> {
    let cli = Cli::parse();
    let txt = read_to_string(&cli.config)
        .map_err(|e| anyhow!("read config file {} error: {}", cli.config, e))?;

    let config: Config = toml::from_str(&txt).map_err(|e| {
        anyhow!("parse config file {} error: {}", cli.config, e)
    })?;

    println!("{:#?}", config);

    let bufmod_cfg = BufmodCfg::from_env();
    if !bufmod_cfg.enabled {
        info!(log, "bufmod: disabled via SOFTNPU_NO_BUFMOD");
    }
    NANO.store(
        std::env::var("SOFTNPU_NANO")
            .map(|v| v == "1")
            .unwrap_or(false),
        Ordering::Relaxed,
    );
    if nano() {
        info!(log, "per-packet nanosecond timing enabled (SOFTNPU_NANO=1)");
    }
    let sw = Switch::new(&config.ports, &bufmod_cfg, &log)?;

    // One pipeline instance per receive loop (two per port: ingress and
    // egress) so the two directions never serialize on a single global
    // lock. Keep every `Library` alive for the program lifetime -- RAII:
    // dropping one would dlclose the .so while pipelines still hold
    // vtable pointers into it.
    let mut libs = Vec::new();
    let mut pipelines: Vec<Arc<Mutex<Box<dyn Pipeline>>>> =
        Vec::with_capacity(2 * sw.ports.len());
    for _ in 0..2 * sw.ports.len() {
        let radix = u16::try_from(config.ports.len() + 1)
            .map_err(|_| anyhow!("too many ports: {}", config.ports.len()))?;
        let (lib, pipe) = load_program(&config.p4_program, radix)?;
        libs.push(lib);
        pipelines.push(Arc::new(Mutex::new(pipe)));
    }
    let stats = Arc::new(Stats::default());

    // Build the per-direction transmit rings and their worker threads first,
    // so the receive threads can hand frames off without ever blocking on tx.
    let mut sidecar_tx = Vec::with_capacity(sw.ports.len());
    let mut scrimlet_tx = Vec::with_capacity(sw.ports.len());
    for (index, port) in sw.ports.iter().enumerate() {
        let frame_max = port.mtu + L2_HEADROOM + 64;
        let s_ring = Arc::new(TxRing::new(TX_QUEUE_DEPTH, frame_max));
        let c_ring = Arc::new(TxRing::new(TX_QUEUE_DEPTH, frame_max));
        sidecar_tx.push(s_ring.clone());
        scrimlet_tx.push(c_ring.clone());

        let sfd = dlpi_raw_fd(port.sidecar);
        let cfd = dlpi_raw_fd(port.scrimlet);
        set_flags_nonblocking(sfd).map_err(|e| {
            anyhow!("setting sidecar port fd nonblocking failed: {}", e)
        })?;
        set_flags_nonblocking(cfd).map_err(|e| {
            anyhow!("setting scrimlet port fd nonblocking failed: {}", e)
        })?;

        let stats_ = stats.clone();
        let log_ = log.clone();
        thread::Builder::new()
            .name(format!("tx-sidecar-{}", index))
            .spawn(move || s_ring.tx_drain(sfd, stats_, log_, index, "sidecar"))
            .expect("spawn tx-sidecar");

        let stats_ = stats.clone();
        let log_ = log.clone();
        thread::Builder::new()
            .name(format!("tx-scrimlet-{}", index))
            .spawn(move || {
                c_ring.tx_drain(cfd, stats_, log_, index, "scrimlet")
            })
            .expect("spawn tx-scrimlet");
    }
    let txq = Arc::new(TxQueues {
        sidecar: sidecar_tx,
        scrimlet: scrimlet_tx,
    });

    for (index, port) in sw.ports.iter().enumerate() {
        let (sidecar_bufmod, scrimlet_bufmod) =
            (port.sidecar_bufmod, port.scrimlet_bufmod);
        let buf_len = if sidecar_bufmod || scrimlet_bufmod {
            (port.mtu + L2_HEADROOM).max(bufmod_cfg.recv_buf(port.mtu))
        } else {
            port.mtu + L2_HEADROOM
        };

        // ingress handler: sidecar rx -> pipeline -> tx queue
        let sw_ = sw.clone();
        let txq_ = txq.clone();
        let pipe_ = pipelines[2 * index].clone();
        let stats_ = stats.clone();
        let log_ = log.clone();
        let fd = dlpi_raw_fd(port.sidecar);
        thread::Builder::new()
            .name(format!("ingress-{}", index))
            .spawn(move || {
                info!(
                    log_,
                    "ingress packet handler running for port {}", index
                );
                let mut scratch = Vec::with_capacity(buf_len);
                recv_loop(
                    fd,
                    buf_len,
                    sidecar_bufmod,
                    stats_.clone(),
                    log_.clone(),
                    move |data| {
                        process_ingress_packet(
                            index,
                            data,
                            &sw_,
                            &txq_,
                            &pipe_,
                            &mut scratch,
                            &stats_,
                            &log_,
                        )
                    },
                );
            })
            .expect("spawn ingress handler");

        // egress handler: scrimlet rx -> pipeline -> tx queue
        let sw_ = sw.clone();
        let txq_ = txq.clone();
        let pipe_ = pipelines[2 * index + 1].clone();
        let stats_ = stats.clone();
        let log_ = log.clone();
        let fd = dlpi_raw_fd(port.scrimlet);
        thread::Builder::new()
            .name(format!("egress-{}", index))
            .spawn(move || {
                info!(log_, "egress packet handler running for port {}", index);
                let mut frame = vec![0u8; buf_len];
                let mut scratch = Vec::with_capacity(buf_len);
                recv_loop(
                    fd,
                    buf_len,
                    scrimlet_bufmod,
                    stats_.clone(),
                    log_.clone(),
                    move |data| {
                        process_egress_packet(
                            index,
                            data,
                            &mut frame,
                            &sw_,
                            &txq_,
                            &pipe_,
                            &mut scratch,
                            &stats_,
                            &log_,
                        );
                    },
                );
            })
            .expect("spawn egress handler");
    }
    spawn_reporter(stats.clone(), log.clone());

    //TODO as parameters
    let server = format!("{}/server", cli.uds_path);
    let client = format!("{}/client", cli.uds_path);

    let _ = std::fs::remove_file(&server);

    let uds = UnixDatagram::bind(&server)
        .map_err(|e| anyhow!("failed to open management socket: {}", e))?;

    loop {
        let mut buf = vec![0u8; 10240];
        let n = match uds.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                error!(log, "management socket recv: {}", e);
                continue;
            }
        };
        let msg: softnpu::ManagementRequest =
            match serde_json::from_slice(&buf[..n]) {
                Ok(msg) => msg,
                Err(_) => continue,
            };

        match &msg {
            softnpu::ManagementRequest::TableAdd(_)
            | softnpu::ManagementRequest::TableRemove(_) => {
                for p in pipelines.iter() {
                    softnpu::handle_management_message(
                        msg.clone(),
                        p,
                        &uds,
                        client.as_ref(),
                        config.ports.len(),
                    )
                    .await;
                }
            }
            _ => {
                softnpu::handle_management_message(
                    msg,
                    &pipelines[0],
                    &uds,
                    client.as_ref(),
                    config.ports.len(),
                )
                .await;
            }
        }
    }
}
