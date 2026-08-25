#[cfg(target_os = "linux")]
pub mod linux {
    use std::net::{IpAddr, Ipv4Addr};

    /// 一张网卡的摘要信息。
    #[derive(Debug, Clone)]
    pub struct Interface {
        pub name: String,
        /// 该网卡绑定的所有地址及前缀长度（prefix_len）
        pub addrs: Vec<(IpAddr, u8)>,
    }

    /// 读取所有本地网卡信息（通过 getifaddrs）。
    pub fn list_interfaces() -> Vec<Interface> {
        let mut result: Vec<Interface> = Vec::new();

        // 用 /proc/net/if_inet6 和 /proc/net/fib_trie 太繁琐；
        // 直接调用 getifaddrs(3) 最简洁，libc crate 已经有封装。
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return result;
            }
            let mut ifa = ifap;
            while !ifa.is_null() {
                let ifa_ref = &*ifa;
                ifa = ifa_ref.ifa_next;

                if ifa_ref.ifa_addr.is_null() {
                    continue;
                }
                // 只关心 UP 的网卡
                if ifa_ref.ifa_flags & libc::IFF_UP as u32 == 0 {
                    continue;
                }

                let family = (*ifa_ref.ifa_addr).sa_family as i32;
                let (ip, prefix_len) = match family {
                    libc::AF_INET => {
                        let sa = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)));
                        let prefix_len = if !ifa_ref.ifa_netmask.is_null() {
                            let nm = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in);
                            u32::from_be(nm.sin_addr.s_addr).count_ones() as u8
                        } else {
                            32
                        };
                        (ip, prefix_len)
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in6);
                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr));
                        let prefix_len = if !ifa_ref.ifa_netmask.is_null() {
                            let nm = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in6);
                            nm.sin6_addr
                                .s6_addr
                                .iter()
                                .map(|b| b.count_ones() as u8)
                                .sum()
                        } else {
                            128
                        };
                        (ip, prefix_len)
                    }
                    _ => continue,
                };

                let name = std::ffi::CStr::from_ptr(ifa_ref.ifa_name)
                    .to_string_lossy()
                    .into_owned();

                // 跳过 loopback
                if ifa_ref.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 {
                    continue;
                }

                if let Some(entry) = result.iter_mut().find(|i| i.name == name) {
                    entry.addrs.push((ip, prefix_len));
                } else {
                    result.push(Interface {
                        name,
                        addrs: vec![(ip, prefix_len)],
                    });
                }
            }
            libc::freeifaddrs(ifap);
        }
        result
    }

    /// 判断 `target` 是否属于 `iface` 的某个子网。
    fn addr_in_interface(iface: &Interface, target: IpAddr) -> bool {
        for (iface_ip, prefix_len) in &iface.addrs {
            if ip_in_subnet(*iface_ip, *prefix_len, target) {
                return true;
            }
        }
        false
    }

    /// 判断 `target` 是否属于以 `base` / `prefix_len` 描述的子网。
    fn ip_in_subnet(base: IpAddr, prefix_len: u8, target: IpAddr) -> bool {
        match (base, target) {
            (IpAddr::V4(b), IpAddr::V4(t)) => {
                if prefix_len == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(prefix_len as u32);
                let b32 = u32::from(b);
                let t32 = u32::from(t);
                (b32 >> shift) == (t32 >> shift)
            }
            (IpAddr::V6(b), IpAddr::V6(t)) => {
                if prefix_len == 0 {
                    return true;
                }
                let b128 = u128::from(b);
                let t128 = u128::from(t);
                let shift = 128u32.saturating_sub(prefix_len as u32);
                (b128 >> shift) == (t128 >> shift)
            }
            _ => false,
        }
    }

    /// 查找目标 IP 所属的网卡名称。
    /// 若目标 IP 恰好是某张网卡自身的地址，则跳过（避免 loopback 式连接）。
    pub fn find_interface_by_addr(target: IpAddr, interfaces: &[Interface]) -> Option<&Interface> {
        for iface in interfaces {
            // 目标 IP 不能是这张网卡自身的地址（避免自连）
            let is_self = iface.addrs.iter().any(|(ip, _)| *ip == target);
            if is_self {
                continue;
            }
            if addr_in_interface(iface, target) {
                return Some(iface);
            }
        }
        None
    }

    /// 从 `/proc/net/route` 读取默认路由（Destination=0, Mask=0）对应的网卡名。
    ///
    /// 文件格式（制表符分隔）：
    /// ```text
    /// Iface  Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    /// eth0   00000000    0101A8C0 0003  0      0   100    00000000 0   0      0
    /// ```
    /// Destination 和 Mask 均为小端十六进制，0x00000000 表示 0.0.0.0。
    pub fn default_route_interface() -> Option<String> {
        let content = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                continue;
            }
            let dest = u32::from_str_radix(fields[1], 16).ok()?;
            let mask = u32::from_str_radix(fields[7], 16).ok()?;
            // 默认路由：Destination=0 且 Mask=0
            if dest == 0 && mask == 0 {
                return Some(fields[0].to_string());
            }
        }
        None
    }

    /// 对 socket fd 设置 `SO_BINDTODEVICE`，将 socket 绑定到指定网卡。
    ///
    /// # Safety
    /// `fd` 必须是有效的 socket 文件描述符。
    pub fn bind_to_interface(
        fd: std::os::unix::io::RawFd,
        iface_name: &str,
    ) -> std::io::Result<()> {
        let name = std::ffi::CString::new(iface_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SO_BINDTODEVICE 需要 CAP_NET_RAW 或 root；在 OpenWrt 上 sing-box/clash 也是这样做的
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr() as *const libc::c_void,
                name.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// 根据目标 IP 自动选择出口网卡并绑定 socket。
    ///
    /// 两步逻辑（与 sing-box AutoDetectInterfaceFunc 一致）：
    ///   1. 目标 IP 属于某张本地网卡的子网 → 绑定该网卡
    ///   2. 否则 → 绑定默认路由网卡
    ///
    /// 任何步骤失败都静默跳过（不影响连接，只是可能走错网卡）。
    pub fn auto_bind_interface(fd: std::os::unix::io::RawFd, target: IpAddr) {
        let interfaces = list_interfaces();

        // 步骤 1：目标 IP 是否属于某张本地网卡的子网
        if let Some(iface) = find_interface_by_addr(target, &interfaces) {
            let _ = bind_to_interface(fd, &iface.name.clone());
            return;
        }

        // 步骤 2：使用默认路由网卡
        if let Some(iface_name) = default_route_interface() {
            let _ = bind_to_interface(fd, &iface_name);
        }
    }
}

// ── 公开 API（跨平台）────────────────────────────────────────────────────────

/// 根据目标地址自动选择出口网卡并绑定 socket（仅 Linux 生效）。
///
/// `fd` 是已创建但尚未 connect 的 socket 文件描述符。
/// 非 Linux 平台为空操作，编译不产生任何代码。
#[cfg(unix)]
#[allow(unused_variables)]
pub fn auto_bind_interface_for_target(fd: std::os::unix::io::RawFd, target: std::net::IpAddr) {
    #[cfg(target_os = "linux")]
    linux::auto_bind_interface(fd, target);
}

/// 将 socket 绑定到指定网卡名称（仅 Linux 生效）。
///
/// 非 Linux 平台为空操作。
#[cfg(unix)]
#[allow(unused_variables)]
pub fn bind_to_interface(fd: std::os::unix::io::RawFd, iface_name: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::bind_to_interface(fd, iface_name);
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

// ── Windows：IP_UNICAST_IF / IPV6_UNICAST_IF 防环回 ────────────────────────
//
// 背景：Linux 用 SO_MARK + `ip rule not fwmark` 把 reflex 自身出站流量排除出
// TUN 的策略路由表；Windows 没有 SO_MARK 这个概念，auto_route 生效后
// （TUN 的默认路由 metric 比物理网卡更优）reflex 自身未绑定网卡的 direct
// 出站 socket 会被系统路由表重新导向 TUN，TUN 又把它当成"新连接"交回
// dispatcher → direct 出站再次发送，形成无限循环（连接数暴涨、CPU/内存
// 迅速耗尽，且往往需要手动重置网络才能恢复）。
//
// 对应方案：与 sing-box / sing-tun Windows 实现一致，用
// `setsockopt(IPPROTO_IP, IP_UNICAST_IF, <ifIndex>)`（IPv6 对应
// `IPPROTO_IPV6, IPV6_UNICAST_IF`）把 socket 强制绑定到 auto_route 生效前
// 探测到的物理网卡，无论系统路由表怎么变，这个 socket 的流量都只从物理网卡
// 发出，不会再被 TUN 截获。
//
// 物理网卡 ifIndex 由 `inbound::tun::platform::windows::setup()` 在添加 TUN
// 路由之前探测并写入这里（此时路由表还没被 TUN 接管，探测结果可信）。
#[cfg(target_os = "windows")]
pub mod windows_iface {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 0 表示"尚未探测到 / 不适用"，有效 ifIndex 从 1 开始。
    static PHYSICAL_IF_INDEX_V4: AtomicU32 = AtomicU32::new(0);
    static PHYSICAL_IF_INDEX_V6: AtomicU32 = AtomicU32::new(0);

    /// 由 TUN 的 Windows setup() 在装 TUN 路由前调用，登记探测到的物理出口网卡。
    pub fn set_physical_if_index_v4(idx: u32) {
        PHYSICAL_IF_INDEX_V4.store(idx, Ordering::Relaxed);
    }

    pub fn set_physical_if_index_v6(idx: u32) {
        PHYSICAL_IF_INDEX_V6.store(idx, Ordering::Relaxed);
    }

    pub fn physical_if_index_v4() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V4.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    pub fn physical_if_index_v6() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V6.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    /// 把已创建（尚未 connect/send）的 socket 绑定到探测到的物理网卡。
    /// 没有探测到物理网卡（未触发 auto_route 防环回逻辑）时为空操作。
    ///
    /// 注意：这里直接用 raw socket handle + `windows` crate 的 WinSock
    /// 绑定，避免引入额外依赖；调用方需保证传入的是合法、尚未关闭的
    /// socket handle。
    pub fn bind_socket_to_physical_interface(raw_socket: std::os::windows::io::RawSocket, target: IpAddr) {
        use ::windows::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF, SOCKET,
        };

        let sock = SOCKET(raw_socket as usize);
        match target {
            IpAddr::V4(_) => {
                if let Some(idx) = physical_if_index_v4() {
                    // IP_UNICAST_IF 要求网络字节序（big-endian）的接口索引。
                    let idx_be: u32 = idx.to_be();
                    let bytes = idx_be.to_ne_bytes();
                    unsafe {
                        let _ = setsockopt(sock, IPPROTO_IP.0, IP_UNICAST_IF, Some(&bytes));
                    }
                }
            }
            IpAddr::V6(_) => {
                if let Some(idx) = physical_if_index_v6() {
                    // IPV6_UNICAST_IF 用主机字节序，无需转换。
                    let bytes = idx.to_ne_bytes();
                    unsafe {
                        let _ = setsockopt(sock, IPPROTO_IPV6.0, IPV6_UNICAST_IF, Some(&bytes));
                    }
                }
            }
        }
    }
}

// ── macOS：IP_BOUND_IF / IPV6_BOUND_IF 防环回 ──────────────────────────────
//
// 跟 Windows 的处境一样：macOS 没有 SO_MARK，`auto_route` 在 macOS 上是靠
// `route add -interface <tun>` 把默认路由整个指向 TUN 网卡实现的（见
// `inbound/tun/platform/macos.rs`），却完全没有对 reflex 自身出站流量做任何
// 排除处理——之前这里唯一能用的是 `route_exclude_address`，但那是要用户手
// 动一条条列出目标 IP 的白名单，不是通用机制。direct 出站本身在 macOS 上
// 也只是个空函数（旧版 `apply_interface_bind` 对非 Linux 的 unix 平台整体
// 空操作），所以 macOS 上以前跟改之前的 Windows 一样，direct 及所有协议出站
// 都可能被 TUN 接管的默认路由重新截获，形成环路。
//
// 对应方案：BSD/Darwin 提供了 `IP_BOUND_IF`（IPv6 对应 `IPV6_BOUND_IF`）这个
// socket 选项，功能与 Linux 的 SO_BINDTODEVICE 等价——把 socket 绑定到指定
// 接口索引，无视路由表。物理网卡的接口索引由
// `inbound::tun::platform::macos::setup()` 在添加 TUN 路由之前探测并写入。
#[cfg(target_os = "macos")]
pub mod macos_iface {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 0 表示"尚未探测到 / 不适用"，有效 ifIndex 从 1 开始。
    static PHYSICAL_IF_INDEX_V4: AtomicU32 = AtomicU32::new(0);
    static PHYSICAL_IF_INDEX_V6: AtomicU32 = AtomicU32::new(0);

    /// 由 TUN 的 macOS setup() 在装 TUN 路由前调用，登记探测到的物理出口网卡。
    pub fn set_physical_if_index_v4(idx: u32) {
        PHYSICAL_IF_INDEX_V4.store(idx, Ordering::Relaxed);
    }

    pub fn set_physical_if_index_v6(idx: u32) {
        PHYSICAL_IF_INDEX_V6.store(idx, Ordering::Relaxed);
    }

    pub fn physical_if_index_v4() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V4.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    pub fn physical_if_index_v6() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V6.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    /// 把已创建（尚未 connect/send）的 socket 绑定到探测到的物理网卡。
    /// 没有探测到物理网卡（未触发 auto_route 防环回逻辑）时为空操作。
    pub fn bind_socket_to_physical_interface(fd: std::os::unix::io::RawFd, target: IpAddr) {
        match target {
            IpAddr::V4(_) => {
                if let Some(idx) = physical_if_index_v4() {
                    unsafe {
                        let _ = libc::setsockopt(
                            fd,
                            libc::IPPROTO_IP,
                            libc::IP_BOUND_IF,
                            &idx as *const u32 as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        );
                    }
                }
            }
            IpAddr::V6(_) => {
                if let Some(idx) = physical_if_index_v6() {
                    unsafe {
                        let _ = libc::setsockopt(
                            fd,
                            libc::IPPROTO_IPV6,
                            libc::IPV6_BOUND_IF,
                            &idx as *const u32 as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        );
                    }
                }
            }
        }
    }
}
