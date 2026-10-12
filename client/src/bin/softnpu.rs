// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Standalone SoftNPU userspace datapath.
//!
//! This is the non-propolis ("sidecar_softnpu" zone) implementation. Unlike
//! the previous revision it does *not* use the async `dlpi::recv_async` path
//! (which registered a fresh `tokio::io::unix::AsyncFd` with the reactor for
//! every single packet, and only ever pulled one packet per wakeup). Instead
//! each port direction runs on its own OS thread using blocking `dlpi::recv`,
//! drains all currently-available packets before blocking again, and reuses
//! all per-packet buffers.
//!
//! Receive and transmit are *decoupled*: each DLPI handle has a dedicated
//! transmit thread fed by a bounded queue. The receive threads only recv,
//! process through the pipeline, and enqueue the resulting frame; they never
//! block on `dlpi::send`. This is important because `dlpi::send` (a `putmsg(2)`
//! on the DLPI stream) can be expensive/blocking, and doing it inline in the
//! receive loop serialises rx and tx and collapses the datapath throughput.
//!
//! The management UDS protocol and the P4 program semantics are unchanged.

use anyhow::{anyhow, Result};
use clap::Parser;
use dlpi::{sys::dlpi_recvinfo_t, DlpiHandle, ResultCode};
use libloading::os::unix::{Library, Symbol, RTLD_NOW};
use slog::{debug, error, info, warn, Drain, Logger};
use softnpu::p4rs::{packet_in, packet_out, Pipeline};
use softnpu_client::cli::get_styles;
use softnpu_client::config::{Config, Port};
use std::fs::read_to_string;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
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
/// Maximum number of frames buffered per transmit direction before we start
/// dropping. Each slot is a heap `Vec<u8>`; 16k frames is a few MB of headroom.
const TX_QUEUE_DEPTH: usize = 16384;

#[derive(Clone)]
pub struct Switch {
    pub ports: Vec<SwitchPort>,
}

#[derive(Clone, Copy)]
pub struct SwitchPort {
    pub sidecar: DlpiHandle,
    pub scrimlet: DlpiHandle,
    pub mtu: usize,
}

/// Per-direction transmit queues. `sidecar[i]` feeds `ports[i].sidecar`,
/// `scrimlet[i]` feeds `ports[i].scrimlet`.
#[derive(Clone)]
struct TxQueues {
    sidecar: Vec<SyncSender<Vec<u8>>>,
    scrimlet: Vec<SyncSender<Vec<u8>>>,
}

impl Switch {
    fn new(ports: &Vec<Port>) -> Result<Switch> {
        Ok(Switch {
            ports: Self::init_ports(ports)?,
        })
    }

    fn init_ports(ports: &Vec<Port>) -> Result<Vec<SwitchPort>> {
        let mut result = Vec::new();
        for p in ports {
            let sidecar =
                Self::init_port(&p.sidecar).map_err(|e| {
                    anyhow!(
                        "initializing sidecar port {} failed: {}",
                        p.sidecar,
                        e,
                    )
                })?;
            let scrimlet = Self::init_port(&p.scrimlet).map_err(|e| {
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
            })
        }
        Ok(result)
    }

    fn init_port(devname: &str) -> Result<DlpiHandle> {
        let p = dlpi::open(devname, dlpi::sys::DLPI_RAW)?;
        dlpi::bind(p, 0x86dd)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_MULTI)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_SAP)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_PHYS)?;
        dlpi::promisc_on(p, dlpi::sys::DL_PROMISC_RX_ONLY)?;
        Ok(p)
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
    fn snapshot(&self) -> [u64; 13] {
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
        ]
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    e.get_ref()
        .and_then(|r| r.downcast_ref::<ResultCode>())
        .map(|rc| *rc == ResultCode::ETimedout)
        .unwrap_or(false)
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

/// Enqueue a fully-built frame for the transmit thread to send. Blocks when
/// the queue is full so a slow TX handler backpressures the receive path.
fn enqueue(
    sender: &SyncSender<Vec<u8>>,
    buf: Vec<u8>,
    stats: &Stats,
    log: &Logger,
) {
    // Blocking send: backpressure through the receive thread (and hence the
    // DLPI stream) is preferable to silently dropping frames.
    if sender.send(buf).is_err() {
        stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
        warn!(log, "tx queue disconnected");
    }
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

    let l0 = Instant::now();
    let mut pl = pipeline.lock().unwrap();
    stats
        .lock_ns
        .fetch_add(l0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    let p0 = Instant::now();
    let output = pl.process_packet((index + 1) as u16, &mut pkt);
    stats
        .process_ns
        .fetch_add(p0.elapsed().as_nanos() as u64, Ordering::Relaxed);
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
    let l0 = Instant::now();
    let mut pl = pipeline.lock().unwrap();
    stats
        .lock_ns
        .fetch_add(l0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    let p0 = Instant::now();
    let output = pl.process_packet((index + 1) as u16, &mut pkt);
    stats
        .process_ns
        .fetch_add(p0.elapsed().as_nanos() as u64, Ordering::Relaxed);
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
    stats: &Stats,
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

    // Hand the frame to the destination port's transmit thread. The receive
    // thread never performs the (potentially blocking) `dlpi::send`.
    scratch.clear();
    scratch.extend_from_slice(&pkt.header_data);
    scratch.extend_from_slice(pkt.payload_data);
    let buf = std::mem::take(scratch);
    enqueue(&txq.sidecar[idx - 1], buf, stats, log);
}

fn send_to_cpu_port(
    pkt: packet_out<'_>,
    switch: &Switch,
    txq: &TxQueues,
    scratch: &mut Vec<u8>,
    stats: &Stats,
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
    let buf = std::mem::take(scratch);
    enqueue(&txq.scrimlet[portnum - 1], buf, stats, log);
}

/// Transmit loop for one DLPI handle: drains its queue and performs the
/// blocking `dlpi::send` off the receive path.
fn tx_loop(
    dh: DlpiHandle,
    rx: Receiver<Vec<u8>>,
    stats: Arc<Stats>,
    log: Logger,
    index: usize,
    dir: &'static str,
) {
    info!(log, "tx handler running for {} port {}", dir, index);
    while let Ok(buf) = rx.recv() {
        let t0 = Instant::now();
        match dlpi::send(dh, &[], buf.as_slice(), None) {
            Ok(_) => {}
            Err(e) => {
                error!(log, "tx ({},{}): {}", dir, index, e);
            }
        }
        stats
            .send_ns
            .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
    }
}

/// Receive loop for one DLPI handle. Blocks for the first packet, then drains
/// everything else that is immediately available before blocking again.
fn recv_loop<F>(
    dh: DlpiHandle,
    buf_len: usize,
    stats: Arc<Stats>,
    log: Logger,
    mut handle: F,
) where
    F: FnMut(&[u8]),
{
    let mut src = [0u8; dlpi::sys::DLPI_PHYSADDR_MAX];
    let mut msg = vec![0u8; buf_len];
    let mut recvinfo = dlpi_recvinfo_t::default();

    loop {
        let t0 = Instant::now();
        let n = match dlpi::recv(dh, &mut src, &mut msg, -1, Some(&mut recvinfo))
        {
            Ok((_, n)) => n,
            Err(e) => {
                stats.rx_err.fetch_add(1, Ordering::Relaxed);
                error!(log, "rx error: {}", e);
                continue;
            }
        };
        stats
            .block_ns
            .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        stats.wakeups.fetch_add(1, Ordering::Relaxed);

        let mut batch = 0u64;
        stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
        stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        let h0 = Instant::now();
        handle(&msg[..n]);
        stats
            .handle_ns
            .fetch_add(h0.elapsed().as_nanos() as u64, Ordering::Relaxed);

        // Drain the rest of the burst without going back to the scheduler.
        loop {
            let r0 = Instant::now();
            let n = match dlpi::recv(dh, &mut src, &mut msg, 0, Some(&mut recvinfo))
            {
                Ok((_, n)) => n,
                Err(e) if is_timeout(&e) => break,
                Err(e) => {
                    stats.rx_err.fetch_add(1, Ordering::Relaxed);
                    error!(log, "rx drain error: {}", e);
                    break;
                }
            };
            stats
                .recv_ns
                .fetch_add(r0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            batch += 1;
            stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
            stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            let h0 = Instant::now();
            handle(&msg[..n]);
            stats
                .handle_ns
                .fetch_add(h0.elapsed().as_nanos() as u64, Ordering::Relaxed);
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
            let avg_proc_us =
                if d(0) > 0 { d(7) as f64 / d(0) as f64 / 1000.0 } else { 0.0 };
            let avg_send_us =
                if d(2) > 0 { d(8) as f64 / d(2) as f64 / 1000.0 } else { 0.0 };
            let avg_lock_us =
                if d(0) > 0 { d(9) as f64 / d(0) as f64 / 1000.0 } else { 0.0 };
            let avg_handle_us =
                if d(0) > 0 { d(10) as f64 / d(0) as f64 / 1000.0 } else { 0.0 };
            let avg_recv_us =
                if d(5) > 0 { d(11) as f64 / d(5) as f64 / 1000.0 } else { 0.0 };
            // Use stdout directly so the numbers show up regardless of the
            // slog env-logger filter.
            println!(
                "STATS rx_pps={:.0} rx_MBps={:.2} tx_pkts={} tx_dropped={} \
                 rx_err={} wakeups={} drained={} multi_batches={} \
                 avg_lock_us={:.2} avg_process_us={:.2} \
                 avg_handle_us={:.2} avg_recv_us={:.2} avg_send_us={:.2}",
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

    let sw = Switch::new(&config.ports)?;

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

    // Build the per-direction transmit queues and their worker threads first,
    // so the receive threads can hand frames off without ever blocking on tx.
    let mut sidecar_tx = Vec::with_capacity(sw.ports.len());
    let mut scrimlet_tx = Vec::with_capacity(sw.ports.len());
    for (index, port) in sw.ports.iter().enumerate() {
        let (s_tx, s_rx) = sync_channel::<Vec<u8>>(TX_QUEUE_DEPTH);
        let (c_tx, c_rx) = sync_channel::<Vec<u8>>(TX_QUEUE_DEPTH);
        sidecar_tx.push(s_tx);
        scrimlet_tx.push(c_tx);

        let dh = port.sidecar;
        let stats_ = stats.clone();
        let log_ = log.clone();
        thread::Builder::new()
            .name(format!("tx-sidecar-{}", index))
            .spawn(move || tx_loop(dh, s_rx, stats_, log_, index, "sidecar"))
            .expect("spawn tx-sidecar");

        let dh = port.scrimlet;
        let stats_ = stats.clone();
        let log_ = log.clone();
        thread::Builder::new()
            .name(format!("tx-scrimlet-{}", index))
            .spawn(move || tx_loop(dh, c_rx, stats_, log_, index, "scrimlet"))
            .expect("spawn tx-scrimlet");
    }
    let txq = Arc::new(TxQueues {
        sidecar: sidecar_tx,
        scrimlet: scrimlet_tx,
    });

    for (index, port) in sw.ports.iter().enumerate() {
        let buf_len = port.mtu + L2_HEADROOM;

        // ingress handler: sidecar rx -> pipeline -> tx queue
        let sw_ = sw.clone();
        let txq_ = txq.clone();
        let pipe_ = pipelines[2 * index].clone();
        let stats_ = stats.clone();
        let log_ = log.clone();
        let dh = port.sidecar;
        thread::Builder::new()
            .name(format!("ingress-{}", index))
            .spawn(move || {
                info!(log_, "ingress packet handler running for port {}", index);
                let mut scratch = Vec::with_capacity(buf_len);
                recv_loop(dh, buf_len, stats_.clone(), log_.clone(), move |data| {
                    process_ingress_packet(
                        index, data, &sw_, &txq_, &pipe_, &mut scratch, &stats_,
                        &log_,
                    )
                });
            })
            .expect("spawn ingress handler");

        // egress handler: scrimlet rx -> pipeline -> tx queue
        let sw_ = sw.clone();
        let txq_ = txq.clone();
        let pipe_ = pipelines[2 * index + 1].clone();
        let stats_ = stats.clone();
        let log_ = log.clone();
        let dh = port.scrimlet;
        thread::Builder::new()
            .name(format!("egress-{}", index))
            .spawn(move || {
                info!(log_, "egress packet handler running for port {}", index);
                let mut frame = vec![0u8; buf_len];
                let mut scratch = Vec::with_capacity(buf_len);
                recv_loop(dh, buf_len, stats_.clone(), log_.clone(), move |data| {
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
                });
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
