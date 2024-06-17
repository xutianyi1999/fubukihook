use socket2::TcpKeepalive;
use std::io::Result;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::time::Duration;

#[allow(unused)]
pub trait SocketExt {
    fn set_keepalive(&self) -> Result<()>;

    fn set_recv_buffer_size(&self, size: usize) -> Result<()>;

    fn set_send_buffer_size(&self, size: usize) -> Result<()>;

    fn bind_device(&self, _interface: &str, _ipv6: bool) -> Result<()>;
}

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(Duration::from_secs(120));

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_device<T: std::os::unix::io::AsFd>(
    socket: &T,
    interface: &str,
    _ipv6: bool
) -> Result<()> {
    let socket = socket2::SockRef::from(socket);
    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(target_os = "macos")]
fn bind_device<T: std::os::unix::io::AsFd>(
    socket: &T,
    interface: &str,
    ipv6: bool
) -> Result<()> {
    use std::num::NonZeroU32;

    let socket = socket2::SockRef::from(socket);

    let index = netconfig::Interface::try_from_name(interface)
        .and_then(|i| i.index())
        .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    if ipv6 {
        socket.bind_device_by_index_v6(NonZeroU32::new(index))
    } else {
        socket.bind_device_by_index_v4(NonZeroU32::new(index))
    }
}

#[cfg(windows)]
fn bind_device<T: std::os::windows::io::AsSocket>(
    socket: &T,
    interface: &str,
    ipv6: bool,
) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    use netconfig::sys::InterfaceExt;

    let index = netconfig::Interface::try_from_alias(interface)
        .and_then(|i| i.index())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let raw = socket.as_socket().as_raw_socket();

    unsafe {
        let code = if ipv6 {
            windows::Win32::Networking::WinSock::setsockopt(
                windows::Win32::Networking::WinSock::SOCKET(raw as usize),
                windows::Win32::Networking::WinSock::IPPROTO_IPV6.0,
                windows::Win32::Networking::WinSock::IPV6_UNICAST_IF,
                Some(&index.to_be_bytes()),
            )
        } else {
            windows::Win32::Networking::WinSock::setsockopt(
                windows::Win32::Networking::WinSock::SOCKET(raw as usize),
                windows::Win32::Networking::WinSock::IPPROTO_IP.0,
                windows::Win32::Networking::WinSock::IP_UNICAST_IF,
                Some(&index.to_be_bytes()),
            )
        };

        if code != 0 {
            return Err(io::Error::last_os_error());
        }
    };

    Ok(())
}

pub fn get_interface_addr(dest_addr: SocketAddr) -> Result<IpAddr> {
    let bind_addr = match dest_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let socket = std::net::UdpSocket::bind((bind_addr, 0))?;
    socket.connect(dest_addr)?;
    let addr = socket.local_addr()?;
    Ok(addr.ip())
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub fn find_interface(ip: IpAddr) -> Result<String> {
    #[allow(unused_imports)]
    use netconfig::sys::InterfaceExt;

    let ifs = netconfig::list_interfaces()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    for inter in ifs {
        let addrs = inter.addresses()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        for addr in addrs {
            if addr.addr() == ip {
                #[cfg(windows)]
                    let if_name = inter.alias();

                #[cfg(unix)]
                    let if_name = inter.name();

                return if_name.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::InvalidInput, "interface not found"))
}

macro_rules! build_socket_ext {
    ($type:path) => {
        impl<T: $type> SocketExt for T {
            fn set_keepalive(&self) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_tcp_keepalive(&TCP_KEEPALIVE)
            }

            fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_recv_buffer_size(size)
            }

            fn set_send_buffer_size(&self, size: usize) -> Result<()> {
                let sock_ref = socket2::SockRef::from(self);
                sock_ref.set_send_buffer_size(size)
            }

            fn bind_device(&self, interface: &str, ipv6: bool) -> Result<()> {
                bind_device(self, interface, ipv6)
            }
        }
    };
}

#[cfg(windows)]
build_socket_ext!(std::os::windows::io::AsSocket);

#[cfg(unix)]
build_socket_ext!(std::os::unix::io::AsFd);

macro_rules! get {
    ($slice: expr, $index: expr, $error_msg: expr) => {
        $slice
            .get($index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, $error_msg))?
    };
    ($slice: expr, $index: expr) => {
        get!($slice, $index, "decode error")
    };
}

#[allow(unused)]
const SRC_ADDR: Range<usize> = 12..16;
const DST_ADDR: Range<usize> = 16..20;

pub fn get_ip_dst_addr(ip_packet: &[u8]) -> Result<Ipv4Addr> {
    let mut buff = [0u8; 4];
    buff.copy_from_slice(get!(
        ip_packet,
        DST_ADDR,
        "get packet source address failed"
    ));
    Ok(Ipv4Addr::from(buff))
}

#[allow(unused)]
pub fn get_ip_src_addr(ip_packet: &[u8]) -> Result<Ipv4Addr> {
    let mut buff = [0u8; 4];
    buff.copy_from_slice(get!(
        ip_packet,
        SRC_ADDR,
        "get packet destination address failed"
    ));
    Ok(Ipv4Addr::from(buff))
}