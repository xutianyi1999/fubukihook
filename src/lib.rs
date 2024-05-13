#[macro_use]
extern crate log;

use std::ffi::{c_char, c_void};
use std::fs;
use std::io::{self, BufRead, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::{ArcSwap, Cache};
use chrono::Utc;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ipnet::Ipv4Net;
use iprange::IpRange;
use net::get_interface_addr;
use netstack_lwip::NetStack;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::runtime::Runtime;

use crate::net::{find_interface, get_ip_dst_addr, SocketExt};

mod net;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
enum Direction {
    Output,
    Input,
}

type InterfacesInfo = extern "C" fn(ctx: *const c_void, info_json: *mut c_char);
type PacketSend =
    extern "C" fn(ctx: *const c_void, direction: Direction, packet: *const u8, len: usize);

#[repr(C)]
#[derive(Copy, Clone)]
struct ExternalContext {
    ctx: *const c_void,
    interfaces_info_fn: InterfacesInfo,
    packet_send_fn: PacketSend,
}

unsafe impl Send for ExternalContext {}
unsafe impl Sync for ExternalContext {}

enum Rule {
    Match(IpRange<Ipv4Net>),
    #[allow(unused)]
    NotMatch(IpRange<Ipv4Net>),
}

impl Rule {
    fn is_proxy(&self, target: &Ipv4Addr) -> bool {
        match &self {
            Rule::Match(range) => range.contains(target),
            Rule::NotMatch(range) => !range.contains(target),
        }
    }
}

async fn udp_inbound_handler(
    udp_inbound: Box<netstack_lwip::UdpSocket>,
    device: Arc<String>,
) -> Result<()> {
    let mapping: Arc<ArcSwap<Vec<Arc<(SocketAddr, UdpSocket, AtomicI64)>>>> =
        Arc::new(ArcSwap::from_pointee(Vec::new()));
    let (tx, mut rx) = netstack_lwip::UdpSocket::split(udp_inbound);
    let tx = Arc::new(tx);

    let mut mapping_cache = Cache::new(&*mapping);

    while let Some((pkt, from, to)) = rx.next().await {
        let snap = mapping_cache.load();

        let item = snap
            .binary_search_by_key(&from, |v| (**v).0)
            .ok()
            .map(|i| &*snap.deref()[i]);

        let insert_item;

        let (_, to_socket, update_time) = match item {
            None => {
                let bind_addr = match to {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };

                let to_socket = UdpSocket::bind(bind_addr).await?;
                SocketExt::bind_device(&to_socket, &device, to.is_ipv6())?;
                insert_item = Arc::new((from, to_socket, AtomicI64::new(Utc::now().timestamp())));

                mapping.rcu(|v| {
                    let mut tmp = (**v).clone();

                    match tmp.binary_search_by_key(&from, |v| (**v).0) {
                        Ok(_) => unreachable!(),
                        Err(i) => tmp.insert(i, insert_item.clone()),
                    }
                    tmp
                });

                tokio::spawn({
                    let tx = tx.clone();
                    let mapping = mapping.clone();
                    let insert_item = insert_item.clone();

                    async move {
                        let (_, to_socket, update_time) = &*insert_item;
                        let mut buff = vec![0u8; 65536];

                        let fut1 = async {
                            loop {
                                let (len, peer) = to_socket.recv_from(&mut buff).await?;
                                debug!("recv from {} to {}", to, from);
                                tx.send_to(&buff[..len], &peer, &from)?;
                                update_time.store(Utc::now().timestamp(), Ordering::Relaxed);
                            }
                        };

                        let fut2 = async {
                            loop {
                                tokio::time::sleep(Duration::from_secs(5)).await;

                                if Utc::now().timestamp() - update_time.load(Ordering::Relaxed)
                                    > 300
                                {
                                    return;
                                }
                            }
                        };

                        let res: io::Result<()> = tokio::select! {
                            res = fut1 => res,
                            _ = fut2 => Ok(())
                        };

                        if let Err(e) = res {
                            error!("child udp handler error: {}", e);
                        }

                        mapping.rcu(|v| {
                            let mut tmp = (**v).clone();

                            match tmp.binary_search_by_key(&from, |v| (**v).0) {
                                Ok(i) => tmp.remove(i),
                                Err(_) => unreachable!(),
                            };
                            tmp
                        });
                    }
                });

                &*insert_item
            }
            Some(v) => v,
        };

        debug!("{} send to {}", from, to);
        to_socket.send(&pkt).await?;
        update_time.store(Utc::now().timestamp(), Ordering::Relaxed);
    }
    Ok(())
}

async fn tcp_inbound_handler(
    mut listener: netstack_lwip::TcpListener,
    device: Arc<String>,
) -> Result<()> {
    while let Some((mut inbound_stream, _local_addr, remote_addr)) = listener.next().await {
        let device = device.clone();

        tokio::spawn(async move {
            let fut = async {
                let socket = if remote_addr.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };

                SocketExt::bind_device(&socket, &device, remote_addr.is_ipv6())?;

                let mut outbound_stream = socket
                    .connect(remote_addr)
                    .await
                    .with_context(|| format!("connect to {} error", &remote_addr))?;

                tokio::io::copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await?;
                Result::<_, anyhow::Error>::Ok(())
            };

            if let Err(e) = fut.await {
                error!("tcp_inbound_handler error: {:?}", e);
            }
        });
    }
    Ok(())
}

async fn netstatck_handler(mut stack_stream: SplitStream<NetStack>, ectx: ExternalContext) -> Result<()> {
    while let Some(pkt) = stack_stream.next().await {
        let pkt = pkt?;
        (ectx.packet_send_fn)(ectx.ctx, Direction::Input, pkt.as_ptr(), pkt.len());
    }
    Ok(())
}

async fn netstatck_sink_handler(
    mut netstack_sink: SplitSink<NetStack, Vec<u8>>,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(pkg) = rx.recv().await {
        netstack_sink.send(pkg).await?;
    }
    Ok(())
}

struct HookHandle {
    _rt: Runtime,
    netstatck_sink_handler_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rule: Rule,
}

fn parse_rules(file_path: &str) -> Result<IpRange<Ipv4Net>> {
    let mut file = fs::File::open(file_path)?;
    let mut buff = Vec::with_capacity(file.metadata()?.len() as usize);
    file.read_to_end(&mut buff)?;

    let mut lines = Cursor::new(buff).lines();
    let mut ip_range = IpRange::new();

    while let Some(res) = lines.next() {
        let line = res?;
        ip_range.add(Ipv4Net::from_str(&line)?);
    }

    ip_range.simplify();
    Ok(ip_range)
}

fn logger_init() -> Result<()> {
    fn init() -> Result<()> {
        use log4rs::append::console::ConsoleAppender;
        use log4rs::config::{Appender, Root};
        use log4rs::encode::pattern::PatternEncoder;
        use log::LevelFilter;

        let pattern = if cfg!(debug_assertions) {
            "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {f}:{L} - {m}{n}"
        } else {
            "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}"
        };

        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(pattern)))
            .build();

        let config = log4rs::Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(
                Root::builder()
                    .appender("stdout")
                    .build(LevelFilter::from_str(
                        std::env::var("FUBUKIHOOK_LOG").as_deref().unwrap_or("ERROR"),
                    )?),
            )?;

        log4rs::init_config(config)?;
        Ok(())
    }

    static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

    LOGGER_INIT.call_once(|| {
        init().expect("logger initialization failed");
    });
    Ok(())
}

#[no_mangle]
extern "C" fn create_hooks(fubuki_ctx: ExternalContext) -> *mut HookHandle {
    let lan_ip = get_interface_addr(SocketAddr::new([1, 1, 1, 1].into(), 53)).unwrap();
    let device = find_interface(lan_ip).unwrap();
    let device = Arc::new(device);
    let rt = Runtime::new().unwrap();
    logger_init().unwrap();

    let netstack_sink_tx = rt.block_on(async {
        let (stack, tcp_listener, udp_socket) = netstack_lwip::NetStack::new().unwrap();
        let (stack_sink, stack_stream) = stack.split();
        let (netstack_sink_tx, netstack_sink_rx) = tokio::sync::mpsc::channel(1024);
        
        tokio::spawn({
            let device = device.clone();
            async move {
                if let Err(e) = tcp_inbound_handler(tcp_listener, device).await {
                    error!("tcp_inbound_handler error: {:?}", e);
                }
                error!("tcp_inbound_handler exited");
            }
        });

        tokio::spawn(async move {
            if let Err(e) = udp_inbound_handler(udp_socket, device).await {
                error!("udp_inbound_handler error: {:?}", e);
            }
            error!("udp_inbound_handler exited");
        });

        tokio::spawn(async move {
            if let Err(e) = netstatck_handler(stack_stream, fubuki_ctx).await {
                error!("netstack_handler error: {:?}", e);
            }
            error!("netstatck_handler exited");
        });

        tokio::spawn(async move {
            if let Err(e) = netstatck_sink_handler(stack_sink, netstack_sink_rx).await {
                error!("netstatck_sink_handler error: {:?}", e);
            }
            error!("netstatck_sink_handler exited");
        });

        netstack_sink_tx
    });

    let file_path = std::env::var("FUBUKI_RULES_FILE").unwrap();
    let rule = Rule::Match(parse_rules(&file_path).unwrap());

    let hook = HookHandle {
        _rt: rt,
        netstatck_sink_handler_tx: netstack_sink_tx,
        rule,
    };

    Box::into_raw(Box::new(hook))
}

#[no_mangle]
extern "C" fn drop_hooks(handle: *mut HookHandle) {
    let _ = unsafe { Box::from_raw(handle) };
}

#[repr(C)]
struct Input {
    direction: Direction,
    packet: *mut u8,
    len: usize,
}

#[repr(C)]
#[allow(unused)]
enum PacketRecvOutput {
    Accept = 0,
    Drop,
}

#[no_mangle]
extern "C" fn packet_recv(handle: &HookHandle, input: &mut Input, output: &mut PacketRecvOutput) {
    if input.direction != Direction::Output {
        return;
    }

    let packet = unsafe { std::slice::from_raw_parts(input.packet, input.len) };
    let dst = match get_ip_dst_addr(packet) {
        Ok(v) => v,
        Err(e) => {
            error!("parse ipv4 packet error: {}", e);
            return;
        }
    };

    if !handle.rule.is_proxy(&dst) {
        return;
    }

    let _ = handle.netstatck_sink_handler_tx.try_send(packet.to_vec());
    *output = PacketRecvOutput::Drop;
}
