#[macro_use]
extern crate log;

use std::ffi::{c_char, c_void};
use std::fs;
use std::future::Future;
use std::io::{self, BufRead, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use futures_util::stream::{SplitSink, SplitStream};
use ipnet::Ipv4Net;
use iprange::IpRange;
use netstack_lwip::NetStack;
use tokio::net::TcpSocket;
use tokio::runtime::Runtime;

use net::get_interface_addr;

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

struct NetStackSendHalf {
    inner: netstack_lwip::UdpSocketSendHalf
}

impl udpproxi::UdpProxiSender for NetStackSendHalf {
    fn send<'a>(&'a self, packet: &'a [u8], from: SocketAddr, to: SocketAddr) -> impl Future<Output=io::Result<()>> + 'a + Send {
        let res = self.inner.send_to(packet, &from, &to);
        std::future::ready(res)
    }
}

async fn udp_inbound_handler(
    udp_inbound: Pin<Box<netstack_lwip::UdpSocket>>,
    device: Arc<String>,
) -> Result<()> {
    let (tx, mut rx) = netstack_lwip::UdpSocket::split(udp_inbound);
    let tx = Arc::new(NetStackSendHalf{inner: tx});

    let mut proxy = udpproxi::UdpProxi::new(tx, move |_from, to| {
        let device = device.clone();

        async move {
            let bind_addr = match to {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };

            let to_socket = tokio::net::UdpSocket::bind(bind_addr).await?;
            SocketExt::bind_device(&to_socket, &device, to.is_ipv6())?;
            Ok(to_socket)
        }
    });

    while let Some((pkt, from, to)) = rx.next().await {
        proxy.send_packet(&pkt, from, to).await?;
    }
    Ok(())
}

async fn tcp_inbound_handler(
    mut listener: Pin<Box<netstack_lwip::TcpListener>>,
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

async fn netstatck_handler(mut stack_stream: SplitStream<Pin<Box<NetStack>>>, ectx: ExternalContext) -> Result<()> {
    while let Some(pkt) = stack_stream.next().await {
        let pkt = pkt?;
        (ectx.packet_send_fn)(ectx.ctx, Direction::Input, pkt.as_ptr(), pkt.len());
    }
    Ok(())
}

async fn netstatck_sink_handler(
    mut netstack_sink: SplitSink<Pin<Box<NetStack>>, Vec<u8>>,
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

fn parse_rules(file_path_list: &[&str]) -> Result<IpRange<Ipv4Net>> {
    let mut ip_range = IpRange::new();

    for file_path in file_path_list {
        let mut file = fs::File::open(file_path)?;
        let mut buff = Vec::with_capacity(file.metadata()?.len() as usize);
        file.read_to_end(&mut buff)?;

        let mut lines = Cursor::new(buff).lines();

        while let Some(res) = lines.next() {
            let line = res?;
            ip_range.add(Ipv4Net::from_str(&line)?);
        }
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

    let file_path_list = std::env::var("FUBUKI_RULES_FILE").unwrap();
    let file_path_list = file_path_list.trim().split(',').collect::<Vec<_>>();
    let rule = Rule::Match(parse_rules(&file_path_list).unwrap());

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
