use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::Command,
};
use tracing::{info, warn};

use super::SetupState;
use crate::config::TunInboundConfig;

// Windows 平台：接口 LUID 类型（setup/teardown 路由辅助函数使用）
#[cfg(windows)]
use ::windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
#[cfg(windows)]
use ::windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[cfg(target_arch = "x86_64")]
const EMBEDDED_WINTUN: &[u8] = include_bytes!("../assets/wintun/wintun-amd64.dll");
#[cfg(target_arch = "x86")]
const EMBEDDED_WINTUN: &[u8] = include_bytes!("../assets/wintun/wintun-x86.dll");

pub fn extract_embedded_wintun() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("reflex-wintun.dll");

    // 已存在且大小一致 → 复用，避免占用时写入失败
    let need_write = match std::fs::metadata(&path) {
        Ok(meta) => meta.len() as usize != EMBEDDED_WINTUN.len(),
        Err(_) => true,
    };

    if need_write {
        // 先写到 .tmp 再原子 rename，避免半写文件被其他实例加载
        let mut tmp = path.clone();
        tmp.set_extension("dll.tmp");
        match std::fs::write(&tmp, EMBEDDED_WINTUN) {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    // rename 失败（跨卷 / DLL 被锁）→ 尝试直接覆盖目标
                    warn!(err = %e, "tun: rename wintun.dll.tmp failed, trying direct write");
                    let _ = std::fs::write(&path, EMBEDDED_WINTUN);
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                warn!(err = %e, path = %path.display(), "tun: failed to extract embedded wintun.dll");
            }
        }
    }

    if path.exists() {
        info!(path = %path.display(), size = EMBEDDED_WINTUN.len(), "tun: embedded wintun.dll ready");
    }
    path
}

// ── 地址辅助 ──────────────────────────────────────────────────────────────────

fn parse_addr_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let prefix_len: u8 = len_str.parse().ok()?;
    let max_len = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_len {
        return None;
    }
    Some((ip, prefix_len))
}

fn prefix_len_to_mask_v4(len: u8) -> Ipv4Addr {
    if len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = !((1u32 << (32 - len.min(32))) - 1);
    Ipv4Addr::from(mask)
}

// Windows 路由子网：对齐 sing-tun BuildAutoRouteRanges（非 darwin 分支）。
// 未配置 route_address 时直接劫持默认路由 0.0.0.0/0 + ::/0（TUN 接口 metric=0
// 保证优先级高于物理默认路由），而非旧实现的 8 条分段子网（漏 0.0.0.0/8）。

fn tun_routes_v4(cfg: &TunInboundConfig) -> Vec<String> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(_), _)) => Some(s.clone()),
                _ => None,
            })
            .collect()
    } else {
        vec!["0.0.0.0/0".to_string()]
    }
}

fn tun_routes_v6(cfg: &TunInboundConfig) -> Vec<String> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(_), _)) => Some(s.clone()),
                _ => None,
            })
            .collect()
    } else {
        vec!["::/0".to_string()]
    }
}

fn exclude_routes_v4(cfg: &TunInboundConfig) -> Vec<String> {
    cfg.route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V4(_), _)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn exclude_routes_v6(cfg: &TunInboundConfig) -> Vec<String> {
    cfg.route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V6(_), _)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

// ── Win32 API 路由管理（替代 netsh）──────────────────────────────────────────
//
// 使用 Win32 IP Helper API 原生管理路由、地址和 DNS。
// 参考 clash-rs `routes/windows.rs` 的 CreateIpForwardEntry2 / SetInterfaceDnsSettings 实现。

#[cfg(windows)]
mod win32_route {
    use ::windows::core::{GUID, PCWSTR};
    use ::windows::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;
    use ::windows::Win32::NetworkManagement::IpHelper::*;
    use ::windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use ::windows::Win32::Networking::WinSock::{
        IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, RouterDiscoveryDisabled,
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET,
    };
    use anyhow::anyhow;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tracing::{debug, error};

    fn encode_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 通过接口名获取 LUID（ConvertInterfaceNameToLuidW，对齐 sing-tun winipcfg.LUID）。
    /// 相比 PowerShell 查询：更快、无进程启动开销、无引号注入问题。
    pub fn get_interface_luid(if_name: &str) -> Option<NET_LUID_LH> {
        let name_w = encode_wide(if_name);
        let mut luid = NET_LUID_LH::default();
        let r = unsafe { ConvertInterfaceNameToLuidW(PCWSTR(name_w.as_ptr()), &mut luid) };
        if r.0 != 0 {
            // wintun 接口的 InterfaceAlias 可能与 FriendlyName 不一致，
            // 这是常态而非错误（err=123），调用方有 ifIndex 反查 LUID 兜底，
            // 这里降为 debug 避免每次启动刷告警。
            debug!(
                if_name,
                err = r.0,
                "tun: ConvertInterfaceNameToLuidW failed (alias differs from FriendlyName)"
            );
            return None;
        }
        Some(luid)
    }

    /// 通过 ifIndex 反查 LUID（ConvertInterfaceIndexToLuid）。
    /// 当名字解析（ConvertInterfaceNameToLuidW）因 wintun 接口 alias 与
    /// FriendlyName 不一致而失败（err=123，见 setup 中的 fallback）时使用。
    pub fn luid_from_index(if_index: u32) -> Option<NET_LUID_LH> {
        let mut luid = NET_LUID_LH::default();
        if unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) }.0 == 0 {
            Some(luid)
        } else {
            None
        }
    }

    /// 通过接口名获取 ifIndex（Win32 优先，PowerShell 兜底）。
    pub fn get_if_index(if_name: &str) -> Option<u32> {
        if let Some(luid) = get_interface_luid(if_name) {
            let mut index = 0u32;
            if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) }.0 == 0 {
                return Some(index);
            }
        }
        // fallback：PowerShell（兼容 FriendlyName 与 alias 不一致的场景）
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex"
                ),
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        s.parse().ok()
    }

    /// 通过 ifIndex 获取接口 GUID（用于 SetInterfaceDnsSettings）
    pub fn get_interface_guid(if_index: u32) -> Option<GUID> {
        let mut if_row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        if_row.InterfaceIndex = if_index;
        unsafe { GetIfEntry2(&mut if_row) }.to_hresult().ok().ok()?;
        Some(if_row.InterfaceGuid)
    }

    /// 构建 MIB_IPFORWARD_ROW2（对齐 sing-tun addRouteList：
    /// 以 LUID 为主键、NextHop=网关、metric 显式、生命周期 0xffffffff）。
    fn build_route_row(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: SocketAddr,
        prefix_len: u8,
        gateway: SocketAddr,
        metric: u32,
    ) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        if let Some(l) = luid {
            row.InterfaceLuid = l;
        }
        if let Some(i) = if_index {
            row.InterfaceIndex = i;
        }
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: destination.into(),
            PrefixLength: prefix_len,
        };
        row.NextHop = gateway.into();
        row.Metric = metric;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;
        row
    }

    fn sockaddr_v4(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 0)
    }
    fn sockaddr_v6(ip: Ipv6Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(ip), 0)
    }

    /// 创建 IPv4 路由条目（CreateIpForwardEntry2，对齐 sing-tun addRouteList）。
    pub fn create_route_v4(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        metric: u32,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v4(destination),
            prefix_len,
            sockaddr_v4(gateway),
            metric,
        );
        unsafe { CreateIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("CreateIpForwardEntry2 failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除 IPv4 路由。
    /// 注意：DeleteIpForwardEntry2 的 key 包含 NextHop，必须与创建时一致，
    /// 因此需要传入 gateway（对齐 sing-tun DeleteRoute 语义）。
    pub fn delete_route_v4(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v4(destination),
            prefix_len,
            sockaddr_v4(gateway),
            0,
        );
        unsafe { DeleteIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("DeleteIpForwardEntry2 failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 创建 IPv6 路由条目。
    pub fn create_route_v6(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
        metric: u32,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v6(destination),
            prefix_len,
            sockaddr_v6(gateway),
            metric,
        );
        unsafe { CreateIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("CreateIpForwardEntry2 (v6) failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除 IPv6 路由。
    /// 注意：DeleteIpForwardEntry2 的 key 包含 NextHop，必须与创建时一致，
    /// 因此需要传入 gateway（对齐 sing-tun DeleteRoute 语义）。
    pub fn delete_route_v6(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v6(destination),
            prefix_len,
            sockaddr_v6(gateway),
            0,
        );
        unsafe { DeleteIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("DeleteIpForwardEntry2 (v6) failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 添加接口单播地址（v4，对齐 sing-tun AddIPAddress：DadState=Preferred，
    /// Valid/PreferredLifetime=0xffffffff，SkipAsSource=false）。
    pub fn add_unicast_address(
        if_index: u32,
        addr: Ipv4Addr,
        prefix_len: u8,
    ) -> anyhow::Result<()> {
        let mut s = SOCKADDR_INET::default();
        s.Ipv4.sin_family = AF_INET;
        s.Ipv4.sin_addr.S_un.S_addr = u32::from_le_bytes(addr.octets());

        let row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: if_index,
            Address: s,
            OnLinkPrefixLength: prefix_len,
            PrefixOrigin: IpPrefixOriginManual,
            SuffixOrigin: IpSuffixOriginManual,
            DadState: IpDadStatePreferred,
            ValidLifetime: 0xffffffff,
            PreferredLifetime: 0xffffffff,
            SkipAsSource: false.into(),
            ..Default::default()
        };

        let r = unsafe { CreateUnicastIpAddressEntry(&row) };
        // tun crate 创建适配器时已按配置设置过 v4 地址，这里重复添加会返回
        // ERROR_OBJECT_ALREADY_EXISTS(5010)——视为成功（地址已就位），
        // 避免 Windows 日志里刷"failed to set IPv4 address"告警。
        if r.0 == 0 || r.0 == ERROR_OBJECT_ALREADY_EXISTS.0 {
            Ok(())
        } else {
            Err(anyhow!(
                "CreateUnicastIpAddressEntry failed: Win32 error {}",
                r.0
            ))
        }
    }

    /// 添加接口单播地址（v6）。OnLinkPrefixLength 承载前缀长度。
    pub fn add_unicast_address_v6(
        if_index: u32,
        addr: Ipv6Addr,
        prefix_len: u8,
    ) -> anyhow::Result<()> {
        let mut s = SOCKADDR_INET::default();
        s.Ipv6.sin6_family = AF_INET6;
        s.Ipv6.sin6_addr = addr.into();

        let row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: if_index,
            Address: s,
            OnLinkPrefixLength: prefix_len,
            PrefixOrigin: IpPrefixOriginManual,
            SuffixOrigin: IpSuffixOriginManual,
            DadState: IpDadStatePreferred,
            ValidLifetime: 0xffffffff,
            PreferredLifetime: 0xffffffff,
            SkipAsSource: false.into(),
            ..Default::default()
        };

        let r = unsafe { CreateUnicastIpAddressEntry(&row) };
        if r.0 == 0 || r.0 == ERROR_OBJECT_ALREADY_EXISTS.0 {
            Ok(())
        } else {
            Err(anyhow!(
                "CreateUnicastIpAddressEntry (v6) failed: Win32 error {}",
                r.0
            ))
        }
    }

    /// 删除接口上全部单播地址（对齐 sing-tun FlushIPAddresses）。
    /// 解决 netsh `ipv6 add address` 重启累积堆叠问题（B4）。
    pub fn flush_unicast_addresses(luid: NET_LUID_LH) -> std::io::Result<()> {
        unsafe {
            let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
            let r = GetUnicastIpAddressTable(AF_UNSPEC, &mut table);
            if r.0 != 0 {
                return Err(std::io::Error::other(format!(
                    "GetUnicastIpAddressTable failed: Win32 error {}",
                    r.0
                )));
            }
            if table.is_null() {
                return Ok(());
            }
            let count = (*table).NumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            let mut last_err: Option<u32> = None;
            for row in entries {
                if row.InterfaceLuid.Value == luid.Value {
                    let r2 = DeleteUnicastIpAddressEntry(row);
                    if r2.0 != 0 && last_err.is_none() {
                        last_err = Some(r2.0);
                    }
                }
            }
            FreeMibTable(table as *const core::ffi::c_void);
            match last_err {
                Some(e) => Err(std::io::Error::other(format!(
                    "DeleteUnicastIpAddressEntry failed: Win32 error {e}"
                ))),
                None => Ok(()),
            }
        }
    }

    /// 设置接口参数（对齐 sing-tun configure() 中的 IPInterface 设置）：
    /// - 路由器发现关闭（RouterDiscoveryDisabled）
    /// - 禁用重复地址检测（DadTransmits=0，地址即时可用）
    /// - 关闭无状态/有状态自动配置
    /// - NlMtu 对齐配置
    /// - AutoRoute 时 UseAutomaticMetric=false + Metric=0（保证 TUN 路由优先级）
    /// - IPv4 额外开启 ForwardingEnabled（sing-tun 仅 v4 开启）
    pub fn configure_interface(
        luid: NET_LUID_LH,
        family: ADDRESS_FAMILY,
        mtu: u32,
        auto_route: bool,
        set_forwarding: bool,
    ) -> std::io::Result<()> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = luid;
        let r = unsafe { GetIpInterfaceEntry(&mut row) };
        if r.0 != 0 {
            return Err(std::io::Error::other(format!(
                "GetIpInterfaceEntry failed: Win32 error {}",
                r.0
            )));
        }
        if set_forwarding {
            row.ForwardingEnabled = true.into();
        }
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.DadTransmits = 0;
        row.ManagedAddressConfigurationSupported = false.into();
        row.OtherStatefulConfigurationSupported = false.into();
        row.NlMtu = mtu;
        if auto_route {
            row.UseAutomaticMetric = false.into();
            row.Metric = 0;
        }
        unsafe { SetIpInterfaceEntry(&mut row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("SetIpInterfaceEntry failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 设置接口 DNS 服务器（SetInterfaceDnsSettings WinAPI，参考 clash-rs）。
    /// `servers` 为空时清空接口 DNS（对齐 sing-tun SetDNS(family, nil, nil)）。
    pub fn set_interface_dns(if_index: u32, servers: &[IpAddr]) -> anyhow::Result<()> {
        let guid = get_interface_guid(if_index)
            .ok_or_else(|| anyhow!("interface {if_index} not found"))?;

        let dns_str = servers
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",");
        let mut dns_wstr: Vec<u16> = dns_str.encode_utf16().chain(std::iter::once(0)).collect();

        let dns_settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: ::windows::core::PWSTR::from_raw(dns_wstr.as_mut_ptr()),
            ..Default::default()
        };

        unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow!("SetInterfaceDnsSettings failed: {}", e))
    }

    /// 禁用接口 DNS 动态注册（对齐 sing-tun DisableDNSRegistration）。
    pub fn disable_dns_registration(if_index: u32) -> anyhow::Result<()> {
        let guid = get_interface_guid(if_index)
            .ok_or_else(|| anyhow!("interface {if_index} not found"))?;

        let dns_settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_REGISTRATION_ENABLED as u64,
            RegistrationEnabled: 0,
            ..Default::default()
        };

        unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow!("SetInterfaceDnsSettings (registration) failed: {}", e))
    }
}

// ── WFP (Windows Filtering Platform) 严格路由 ────────────────────────────────
//
// 使用 WFP 原生 API（FwpmEngineOpen0 / FwpmSubLayerAdd0 / FwpmFilterAdd0）实现
// 内核级流量过滤，严格对齐 sing-tun tun_windows.go Start() 的 strict_route：
//
//  1. 打开引擎（FWPM_SESSION_FLAG_DYNAMIC，会话结束自动清理全部过滤器）
//  2. 创建自定义 sublayer（weight = MaxUint16），保证规则优先于系统防火墙
//  3. permit 自身进程（ALE_APP_ID 匹配，weight 13，CLEAR_ACTION_RIGHT）
//     → 防止 block :53 把 reflex 自己的 DNS 出站一起拦掉（代理 DNS 死锁）
//  4. 缺失地址族 block（weight 12）
//  5. permit TUN 接口（LOCAL_INTERFACE_INDEX 匹配，weight 11）
//     → TUN 接口流量不受 block :53 影响（DNS hijack 在 IP 层处理）
//  6. block :53（weight 10，v4+v6）→ 强制其他进程 DNS 走 TUN，防泄漏
//
// 修复说明：旧实现直接 zeroed FWPM_FILTER0 且不设 subLayerKey，
// FwpmFilterAdd0 会因 sublayer 无效而失败（规则静默失效），
// 且缺少自身进程 / TUN 接口 permit（B2，P0）。

#[cfg(windows)]
mod wfp {
    use ::windows::core::{GUID, PCWSTR};
    use ::windows::Win32::Foundation::HANDLE;
    use ::windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use ::windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
    use tracing::{info, warn};

    // 权重对齐 sing-tun：permit 自身进程 > block 缺失地址族 > permit TUN > block DNS
    const WEIGHT_PERMIT_APP: u8 = 13;
    const WEIGHT_BLOCK_FAMILY: u8 = 12;
    const WEIGHT_PERMIT_TUN: u8 = 11;
    const WEIGHT_BLOCK_DNS: u8 = 10;

    fn encode_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// WFP 引擎会话封装。drop 时自动关闭引擎并清理过滤器（FWPM_SESSION_FLAG_DYNAMIC）。
    pub struct WfpSession {
        engine_handle: HANDLE,
        sub_layer_key: GUID,
    }

    impl WfpSession {
        /// 打开 WFP 引擎（需要管理员权限）并创建自定义 sublayer。
        pub fn open() -> std::io::Result<Self> {
            let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            // FWPM_SESSION_FLAG_DYNAMIC: 会话结束时自动删除所有添加的过滤器
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut handle = HANDLE::default();
            let result = unsafe {
                FwpmEngineOpen0(
                    None,
                    RPC_C_AUTHN_DEFAULT as u32, // windows crate 0.58: RPC_C_AUTHN_DEFAULT 是 i32(-1)
                    None,
                    Some(&session),
                    &mut handle,
                )
            };
            if result != 0 {
                return Err(std::io::Error::other(format!(
                    "FwpmEngineOpen0 failed: Win32 error {result}"
                )));
            }

            // 创建自定义 sublayer（sing-tun：Weight = MaxUint16），
            // 让本会话的规则优先于系统防火墙规则。
            let sub_layer_key =
                GUID::new().map_err(|e| std::io::Error::other(format!("CoCreateGuid: {e}")))?;
            let name_w = encode_wide("reflex auto-route rules");
            let desc_w = encode_wide("reflex tun auto-route rules (strict_route)");
            let mut sub_layer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sub_layer.subLayerKey = sub_layer_key;
            sub_layer.displayData = FWPM_DISPLAY_DATA0 {
                name: ::windows::core::PWSTR::from_raw(name_w.as_ptr() as *mut u16),
                description: ::windows::core::PWSTR::from_raw(desc_w.as_ptr() as *mut u16),
            };
            // windows crate 0.58 中 FWPM_SUBLAYER0.weight 直接是 u16（不是
            // FWPM_VALUE 联合），对齐 sing-tun 的 Weight = MaxUint16。
            sub_layer.weight = u16::MAX;
            let result = unsafe { FwpmSubLayerAdd0(handle, &sub_layer, None) };
            if result != 0 {
                let _ = unsafe { FwpmEngineClose0(handle) };
                return Err(std::io::Error::other(format!(
                    "FwpmSubLayerAdd0 failed: Win32 error {result}"
                )));
            }
            info!("tun: WFP engine opened, sublayer created");
            Ok(Self {
                engine_handle: handle,
                sub_layer_key,
            })
        }

        /// 添加过滤器（统一挂到本会话 sublayer）。
        fn add_filter(
            &self,
            layer: GUID,
            weight: u8,
            action_type: FWP_ACTION_TYPE,
            display_name: &str,
            conditions: &mut [FWPM_FILTER_CONDITION0],
            flags: FWPM_FILTER_FLAGS,
        ) -> std::io::Result<()> {
            let name_w = encode_wide(display_name);
            let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            filter.layerKey = layer;
            // ⚠️ subLayerKey 必须指向已添加的 sublayer，否则 FwpmFilterAdd0 失败
            filter.subLayerKey = self.sub_layer_key;
            filter.action.r#type = action_type;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = weight;
            filter.flags = flags;
            filter.displayData = FWPM_DISPLAY_DATA0 {
                name: ::windows::core::PWSTR::from_raw(name_w.as_ptr() as *mut u16),
                description: ::windows::core::PWSTR::from_raw(name_w.as_ptr() as *mut u16),
            };
            filter.filterCondition = conditions.as_mut_ptr();
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterKey =
                GUID::new().map_err(|e| std::io::Error::other(format!("CoCreateGuid: {e}")))?;

            let mut filter_id: u64 = 0;
            let result =
                unsafe { FwpmFilterAdd0(self.engine_handle, &filter, None, Some(&mut filter_id)) };
            if result != 0 {
                return Err(std::io::Error::other(format!(
                    "FwpmFilterAdd0 ({display_name}) failed: Win32 error {result}"
                )));
            }
            Ok(())
        }

        /// permit 当前进程（ALE_APP_ID 匹配，CLEAR_ACTION_RIGHT），v4 + v6。
        /// 防止后续 block 规则拦截 reflex 自身出站（对齐 sing-tun permitFilter4/6）。
        pub fn protect_process(&self, exe_path: &str) -> std::io::Result<()> {
            let exe_w = encode_wide(exe_path);
            let mut appid: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            let result = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(exe_w.as_ptr()), &mut appid) };
            if result != 0 || appid.is_null() {
                return Err(std::io::Error::other(format!(
                    "FwpmGetAppIdFromFileName0 failed: Win32 error {result}"
                )));
            }

            let appid_ref = unsafe { &*appid };
            let mut cond_v4 = self.make_app_id_condition(appid_ref);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WEIGHT_PERMIT_APP,
                FWP_ACTION_PERMIT,
                "reflex protect ipv4",
                std::slice::from_mut(&mut cond_v4),
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            )?;
            let mut cond_v6 = self.make_app_id_condition(appid_ref);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                WEIGHT_PERMIT_APP,
                FWP_ACTION_PERMIT,
                "reflex protect ipv6",
                std::slice::from_mut(&mut cond_v6),
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            )?;

            // 释放 FwpmGetAppIdFromFileName0 分配的内存
            unsafe {
                FwpmFreeMemory0(
                    &mut appid as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void,
                );
            }
            Ok(())
        }

        /// block 缺失地址族（对齐 sing-tun blockFilter：weight 12）。
        pub fn block_family(&self, layer: GUID, name: &str) -> std::io::Result<()> {
            self.add_filter(
                layer,
                WEIGHT_BLOCK_FAMILY,
                FWP_ACTION_BLOCK,
                name,
                &mut [],
                FWPM_FILTER_FLAGS(0),
            )
        }

        /// permit 从 TUN 接口发起的连接（LOCAL_INTERFACE_INDEX 匹配，对齐 sing-tun
        /// tunFilter4/6：weight 11，让 TUN 接口流量不受 block :53 影响）。
        pub fn permit_tun_interface(
            &self,
            layer: GUID,
            if_index: u32,
            name: &str,
        ) -> std::io::Result<()> {
            let mut cond = FWPM_FILTER_CONDITION0 {
                // windows crate 0.58 无 FWPM_CONDITION_LOCAL_INTERFACE_INDEX；
                // ALE_AUTH_CONNECT 层接口条件使用 FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX。
                fieldKey: FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX,
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            cond.conditionValue.r#type = FWP_UINT32;
            cond.conditionValue.Anonymous.uint32 = if_index;
            self.add_filter(
                layer,
                WEIGHT_PERMIT_TUN,
                FWP_ACTION_PERMIT,
                name,
                std::slice::from_mut(&mut cond),
                FWPM_FILTER_FLAGS(0),
            )
        }

        /// block 出站 port 53（v4 + v6，对齐 sing-tun blockDNSFilter4/6：weight 10，
        /// 不带 protocol 条件；reflex 无 DNSMode 概念，恒启用防泄漏）。
        pub fn block_dns(&self) -> std::io::Result<()> {
            let mut cond_v4 = self.make_uint16_condition(FWPM_CONDITION_IP_REMOTE_PORT, 53);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WEIGHT_BLOCK_DNS,
                FWP_ACTION_BLOCK,
                "reflex block ipv4 dns",
                std::slice::from_mut(&mut cond_v4),
                FWPM_FILTER_FLAGS(0),
            )?;
            let mut cond_v6 = self.make_uint16_condition(FWPM_CONDITION_IP_REMOTE_PORT, 53);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                WEIGHT_BLOCK_DNS,
                FWP_ACTION_BLOCK,
                "reflex block ipv6 dns",
                std::slice::from_mut(&mut cond_v6),
                FWPM_FILTER_FLAGS(0),
            )
        }

        fn make_app_id_condition(&self, appid: &FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
            let mut cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            // windows crate 0.58: byteBlob 字段是 *mut FWP_BYTE_BLOB（不是值类型）
            cond.conditionValue.Anonymous.byteBlob =
                appid as *const FWP_BYTE_BLOB as *mut FWP_BYTE_BLOB;
            cond
        }

        fn make_uint16_condition(&self, key: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
            let mut cond = FWPM_FILTER_CONDITION0 {
                fieldKey: key,
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            cond.conditionValue.r#type = FWP_UINT16;
            cond.conditionValue.Anonymous.uint16 = value;
            cond
        }
    }

    impl Drop for WfpSession {
        fn drop(&mut self) {
            if !self.engine_handle.is_invalid() {
                let _ = unsafe { FwpmEngineClose0(self.engine_handle) };
                info!("tun: WFP engine closed (filters auto-removed via DYNAMIC flag)");
            }
        }
    }

    /// 创建完整 strict_route WFP 会话（对齐 sing-tun tun_windows.go Start()）。
    /// 返回堆指针（以 usize 存储），teardown 时调用 `drop_wfp_session` 释放。
    /// 失败返回 0（调用方应忽略并降级）。
    pub fn create_strict_session(
        exe_path: Option<String>,
        if_index: Option<u32>,
        has_v4: bool,
        has_v6: bool,
    ) -> usize {
        let session = match WfpSession::open() {
            Ok(s) => s,
            Err(e) => {
                warn!("tun: WFP session open failed (strict_route disabled): {e}");
                return 0;
            }
        };

        // 1. permit 自身进程（关键：防止 block :53 拦截 reflex 自己的 DNS）
        if let Some(exe) = exe_path {
            if let Err(e) = session.protect_process(&exe) {
                warn!("tun: WFP protect_process failed: {e}");
            }
        } else {
            warn!("tun: cannot determine current exe for WFP process permit");
        }

        // 2. 缺失地址族 block
        if !has_v4 {
            if let Err(e) =
                session.block_family(FWPM_LAYER_ALE_AUTH_CONNECT_V4, "reflex block ipv4")
            {
                warn!("tun: WFP block_family v4 failed: {e}");
            }
        }
        if !has_v6 {
            if let Err(e) =
                session.block_family(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "reflex block ipv6")
            {
                warn!("tun: WFP block_family v6 failed: {e}");
            }
        }

        // 3. permit TUN 接口
        if let Some(idx) = if_index {
            if has_v4 {
                if let Err(e) = session.permit_tun_interface(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    idx,
                    "reflex allow ipv4",
                ) {
                    warn!("tun: WFP permit_tun_interface v4 failed: {e}");
                }
            }
            if has_v6 {
                if let Err(e) = session.permit_tun_interface(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    idx,
                    "reflex allow ipv6",
                ) {
                    warn!("tun: WFP permit_tun_interface v6 failed: {e}");
                }
            }
        }

        // 4. block :53（防 DNS 泄漏）
        if let Err(e) = session.block_dns() {
            warn!("tun: WFP block_dns failed: {e}");
        }

        let boxed = Box::new(session);
        Box::into_raw(boxed) as usize
    }

    /// 释放由 `create_strict_session` 创建的 WFP 会话。
    /// 安全性：ptr 必须由 `create_strict_session` 返回，且只能释放一次。
    pub unsafe fn drop_wfp_session(ptr: usize) {
        if ptr != 0 {
            let _ = Box::from_raw(ptr as *mut WfpSession);
        }
    }
}

// ── 接口名解析 / 等待（由 mod.rs 主流程调用）─────────────────────────────────

/// 通过 PowerShell 查询适配器真实名称。
/// wintun 适配器由 device_guid 唯一标识，名称可能与配置值不同。
/// 适配器创建后网络子系统枚举存在延迟，重试最多 1s（对齐 wait_for_interface 的
/// 轮询思路；B1 修复后 expected 与 tun crate 实际名一致，重试为兜底）。
pub fn resolve_actual_interface_name(expected: &str) -> String {
    for _ in 0..10 {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("(Get-NetAdapter -Name '{expected}' -ErrorAction SilentlyContinue).Name"),
            ])
            .output();
        if let Ok(out) = out {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    warn!(expected = %expected, "tun: could not verify interface name via PowerShell, using configured name");
    expected.to_string()
}

/// 等待 TUN 接口的 IPv4 地址真正可绑定（Windows 配置后延迟）。
pub async fn wait_for_tun_address(addr: Ipv4Addr) {
    use std::net::SocketAddrV4;
    for _ in 0u32..30 {
        match tokio::net::TcpListener::bind(SocketAddrV4::new(addr, 0)).await {
            Ok(_) => return,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }
    warn!(addr = %addr, "tun: address not ready after 6s, proceeding anyway");
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn current_exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

fn get_default_gateway_v4() -> Option<Ipv4Addr> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
             | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse().ok()
}

fn get_default_gateway_v6() -> Option<Ipv6Addr> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue \
             | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse().ok()
}

/// 解析 IPv4 CIDR 为 (addr, prefix_len)。
fn parse_cidr_v4(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let pl: u8 = len_str.parse().ok()?;
    if pl > 32 {
        return None;
    }
    Some((ip, pl))
}

/// 解析 IPv6 CIDR 为 (addr, prefix_len)。
fn parse_cidr_v6(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let pl: u8 = len_str.parse().ok()?;
    if pl > 128 {
        return None;
    }
    Some((ip, pl))
}

/// 等待接口可见（wintun 创建后有延迟）。
fn wait_for_interface(if_name: &str) {
    for _ in 0..30 {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex"
                ),
            ])
            .output()
            .ok();
        if let Some(out) = out {
            if String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .is_ok()
            {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    warn!(interface = %if_name, "tun: interface not visible after 3s");
}

// ── reflex 自身绕过 TUN 路由（防止路由循环）──────────────────────────────────
//
// auto_route 将默认路由指向 TUN 后，reflex 自身出站流量也会进入 TUN 形成循环。
// 解决方式：在添加 TUN 路由前，为 reflex 进程所在主机的 IP 添加一条 host route
// 走物理网关（metric=0，比 TUN 的 metric=1 优先级更高），确保 reflex 自身流量
// 不经过 TUN。该方法与 sing-box Windows 实现思路一致。

struct ReflexBypass {
    v4_route: Option<String>, // "if_idx/gw/reflex_ip" 格式
}

/// 探测 IPv6 物理默认路由所在接口，登记给 interface_finder::windows_iface，
/// 让 direct 出站发往 IPv6 目标的 socket也能用 IPV6_UNICAST_IF 绑定物理网卡，
/// 避免只处理了 IPv4 而 IPv6 流量仍然环回进 TUN。
/// 很多机器没有 IPv6 出口（探测不到属于正常情况），此时安静跳过，不当作错误。
fn register_physical_interface_v6() {
    let if_idx6: Option<u32> = (|| {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex",
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    })();

    if let Some(idx) = if_idx6 {
        crate::interface_finder::windows_iface::set_physical_if_index_v6(idx);
        info!(
            if_idx = idx,
            "tun: registered physical IPv6 interface for direct outbound binding"
        );
    }
}

fn add_reflex_bypass() -> ReflexBypass {
    let mut bypass = ReflexBypass { v4_route: None };

    // IPv6 物理出口网卡登记（用于 IP_UNICAST_IF 绑定，防止 IPv6 direct 流量环回）。
    // 与下面的 IPv4 探测相互独立，即使这里探测不到（无 IPv6 出口）也不影响 IPv4 路径。
    register_physical_interface_v6();

    // 获取物理默认网关所在接口索引和网关 IP
    let if_info: Option<(u32, Ipv4Addr)> = (|| {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex",
            ])
            .output()
            .ok()?;
        let if_idx: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;

        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
            ])
            .output()
            .ok()?;
        let gw: Ipv4Addr = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;

        Some((if_idx, gw))
    })();

    if let Some((if_idx, gw)) = if_info {
        // 把物理网卡 ifIndex 登记给 outbound::common::interface_finder，
        // 供 direct 出站用 IP_UNICAST_IF 把自身 socket 绑定到这张物理网卡，
        // 避免 TUN 接管默认路由后把 reflex 自己的出站流量重新截获形成环路
        // （见 interface_finder.rs windows_iface 模块的说明）。
        crate::interface_finder::windows_iface::set_physical_if_index_v4(if_idx);

        // 获取本机在物理接口上的 IP
        let reflex_ip: Option<String> = (|| {
            let out = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-NetIPAddress -InterfaceIndex {if_idx} -AddressFamily IPv4 \
                              -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress"
                    ),
                ])
                .output()
                .ok()?;
            let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if ip.is_empty() {
                None
            } else {
                Some(ip)
            }
        })();

        if let Some(reflex_ip) = reflex_ip {
            // 幂等：先删后加。上次进程异常退出（未走 teardown）或删除失败时
            // 可能残留 host route，直接 `netsh add` 会因"已存在"失败。
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &format!("{reflex_ip}/32"),
                    &if_idx.to_string(),
                ])
                .output();
            let out = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &format!("{reflex_ip}/32"),
                    &if_idx.to_string(),
                    &gw.to_string(),
                    "metric=0",
                ])
                .output();
            let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
            if ok {
                info!(reflex_ip = %reflex_ip, gateway = %gw, if_idx = if_idx,
                      "tun: added reflex bypass route v4");
                bypass.v4_route = Some(format!("{if_idx}/{gw}/{reflex_ip}"));
            } else {
                let stderr = out
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_default();
                warn!(reflex_ip = %reflex_ip, stderr = %stderr,
                      "tun: failed to add reflex bypass route v4");
            }
        } else {
            warn!("tun: could not determine reflex outbound IP for bypass route");
        }
    } else {
        warn!("tun: could not determine physical gateway for reflex bypass route");
    }

    bypass
}

// ── setup / teardown ──────────────────────────────────────────────────────────

/// 计算 IPv4 地址的下一个地址（对齐 sing-tun HasNextAddress）。
fn next_v4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let v = u32::from(ip);
    if v == u32::MAX {
        None
    } else {
        Some(Ipv4Addr::from(v + 1))
    }
}

/// TUN 服务端地址（网关/DNS）：第一个 v4 地址的下一个。
/// 对齐 sing-tun Inet4GatewayAddr / Inet4DNSAddress 的 Windows 默认行为。
fn server_addr_v4(cfg: &TunInboundConfig) -> Option<Ipv4Addr> {
    cfg.address.iter().find_map(|s| match parse_addr_prefix(s) {
        Some((IpAddr::V4(ip), _)) => next_v4(ip),
        _ => None,
    })
}

fn server_addr_v6(cfg: &TunInboundConfig) -> Option<Ipv6Addr> {
    cfg.address.iter().find_map(|s| match parse_addr_prefix(s) {
        // std 的 Ipv6Addr 无加法方法，用 u128 运算（与 mod.rs has_next_addr_v6 一致）
        Some((IpAddr::V6(ip), _)) => Some(Ipv6Addr::from(u128::from(ip).wrapping_add(1))),
        _ => None,
    })
}

/// 把 auto_route 路由添加到 TUN 接口（Win32 优先，netsh fallback）。
/// 对齐 sing-tun addRouteList：NextHop=网关（server addr），metric=0。
fn add_auto_routes(
    cfg: &TunInboundConfig,
    if_name: &str,
    luid: Option<NET_LUID_LH>,
    if_index: Option<u32>,
    has_v4: bool,
    has_v6: bool,
    state: &mut SetupState,
) {
    let gw_v4 = server_addr_v4(cfg).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let gw_v6 = server_addr_v6(cfg).unwrap_or(Ipv6Addr::UNSPECIFIED);
    if has_v4 {
        for cidr in tun_routes_v4(cfg) {
            let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                (luid, if_index, parse_cidr_v4(&cidr))
            {
                win32_route::create_route_v4(Some(l), Some(i), dest, pl, gw_v4, 0).is_ok()
            } else {
                false
            };
            if !win32_ok {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        &cidr,
                        if_name,
                        "metric=0",
                    ])
                    .output()
                    .ok();
            }
            state.routes_v4.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv4 routes added (metric=0)");
    }
    if has_v6 {
        for cidr in tun_routes_v6(cfg) {
            let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                (luid, if_index, parse_cidr_v6(&cidr))
            {
                win32_route::create_route_v6(Some(l), Some(i), dest, pl, gw_v6, 0).is_ok()
            } else {
                false
            };
            if !win32_ok {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "route",
                        &cidr,
                        if_name,
                        "metric=0",
                    ])
                    .output()
                    .ok();
            }
            state.routes_v6.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv6 routes added (metric=0)");
    }
}

/// 把 route_exclude_address 路由添加到物理网关（Win32 优先，netsh fallback）。
/// 修复 B3：旧实现 netsh 参数错位（网关被放在接口名位置），命令恒失败；
/// teardown 也因缺 interface 参数删不干净。现在统一走 CreateIpForwardEntry2，
/// fallback netsh 也修正为 `prefix interface nexthop metric` 顺序。
fn add_exclude_routes(
    cfg: &TunInboundConfig,
    if_name: &str,
    luid: Option<NET_LUID_LH>,
    if_index: Option<u32>,
    has_v4: bool,
    has_v6: bool,
    state: &mut SetupState,
) {
    if cfg.route_exclude_address.is_empty() {
        return;
    }
    let gw_phys_v4 = get_default_gateway_v4();
    let gw_phys_v6 = get_default_gateway_v6();
    if has_v4 {
        if let Some(gw) = gw_phys_v4 {
            for cidr in exclude_routes_v4(cfg) {
                let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                    (luid, if_index, parse_cidr_v4(&cidr))
                {
                    win32_route::create_route_v4(Some(l), Some(i), dest, pl, gw, 0).is_ok()
                } else {
                    false
                };
                if !win32_ok {
                    // 参数顺序：prefix interface nexthop metric（B3 修复）
                    Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "add",
                            "route",
                            &cidr,
                            if_name,
                            &gw.to_string(),
                            "metric=0",
                        ])
                        .output()
                        .ok();
                }
                state.exclude_routes_v4.push(cidr);
            }
        } else {
            warn!("tun: no IPv4 default gateway, exclude routes skipped");
        }
    }
    if has_v6 {
        if let Some(gw) = gw_phys_v6 {
            for cidr in exclude_routes_v6(cfg) {
                let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                    (luid, if_index, parse_cidr_v6(&cidr))
                {
                    win32_route::create_route_v6(Some(l), Some(i), dest, pl, gw, 0).is_ok()
                } else {
                    false
                };
                if !win32_ok {
                    Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "route",
                            &cidr,
                            if_name,
                            &gw.to_string(),
                            "metric=0",
                        ])
                        .output()
                        .ok();
                }
                state.exclude_routes_v6.push(cidr);
            }
        } else {
            warn!("tun: no IPv6 default gateway, exclude routes skipped");
        }
    }
}

/// 旧版本遗留的 netsh advfirewall strict 规则名（新实现全部走 WFP，清理残留）。
const LEGACY_STRICT_RULE_NAMES: &[&str] = &[
    "reflex-tun-strict-allow-v4",
    "reflex-tun-strict-allow-v6",
    "reflex-tun-strict-allow-tun-v4",
    "reflex-tun-strict-block-tun-v4",
    "reflex-tun-strict-block-v4",
    "reflex-tun-strict-block-v6",
    "reflex-tun-strict-allow-udp",
    "reflex-tun-strict-allow-tcp",
    "reflex-tun-strict-allow-tun",
    "reflex-tun-strict-block-udp",
    "reflex-tun-strict-block-tcp",
    "reflex-tun-strict-block-tun",
];

pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    if !cfg.include_interface.is_empty() || !cfg.exclude_interface.is_empty() {
        warn!("tun: include/exclude_interface not supported on Windows");
    }
    if !cfg.include_uid.is_empty() || !cfg.exclude_uid.is_empty() {
        warn!("tun: include/exclude_uid not supported on Windows");
    }

    let mut state = SetupState::default();
    wait_for_interface(if_name);

    // 在添加 TUN 路由前先添加 reflex 绕过路由（解决路由循环）
    let _reflex_bypass = add_reflex_bypass();

    // 解析配置地址
    let mut v4_addrs: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut v6_addrs: Vec<(Ipv6Addr, u8)> = Vec::new();
    for addr_str in &cfg.address {
        match parse_addr_prefix(addr_str) {
            Some((IpAddr::V4(ip), pl)) => v4_addrs.push((ip, pl)),
            Some((IpAddr::V6(ip), pl)) => v6_addrs.push((ip, pl)),
            None => warn!(addr = %addr_str, "tun: invalid address prefix"),
        }
    }
    let has_v4 = !v4_addrs.is_empty();
    let has_v6 = !v6_addrs.is_empty();

    // 接口索引 + LUID（Win32，替代 PowerShell 查询）
    let if_index = win32_route::get_if_index(if_name);
    // wintun 接口的 InterfaceAlias 可能与 FriendlyName 不一致，
    // ConvertInterfaceNameToLuidW 会返回 err=123；此时用 ifIndex 反查 LUID
    // 兜底，保证 flush_unicast_addresses / 路由等 LUID 路径可用。
    let if_luid = win32_route::get_interface_luid(if_name)
        .or_else(|| if_index.and_then(win32_route::luid_from_index));
    if if_index.is_none() || if_luid.is_none() {
        warn!(interface = %if_name, "tun: interface not resolvable via Win32 API (netsh fallback)");
    }

    // ── 1. 配置 IP 地址：先 flush 再 add（对齐 sing-tun SetIPAddressesForFamily）──
    // 修复 B4：旧实现 netsh `ipv6 add address` 累积堆叠，重启后 IPv6 地址成倍残留。
    if let Some(luid) = if_luid {
        if let Err(e) = win32_route::flush_unicast_addresses(luid) {
            warn!(err = %e, "tun: flush unicast addresses failed (continuing)");
        }
    }
    for (ip, pl) in &v4_addrs {
        if let Some(idx) = if_index {
            if win32_route::add_unicast_address(idx, *ip, *pl).is_ok() {
                info!(interface = %if_name, ip = %ip, "tun: IPv4 address configured (Win32)");
                continue;
            }
        }
        // netsh fallback
        let mask = prefix_len_to_mask_v4(*pl);
        let ok = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "address",
                "name",
                if_name,
                "static",
                &ip.to_string(),
                &mask.to_string(),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            info!(interface = %if_name, ip = %ip, "tun: IPv4 address configured (netsh)");
        } else {
            warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv4 address");
        }
    }
    for (ip, pl) in &v6_addrs {
        if let Some(idx) = if_index {
            if win32_route::add_unicast_address_v6(idx, *ip, *pl).is_ok() {
                info!(interface = %if_name, ip = %ip, "tun: IPv6 address configured (Win32)");
                continue;
            }
        }
        let ok = Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "address",
                if_name,
                &format!("{ip}/{pl}"),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            info!(interface = %if_name, ip = %ip, "tun: IPv6 address configured (netsh)");
        } else {
            warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv6 address");
        }
    }

    // ── 2. 接口参数（对齐 sing-tun configure()：DAD 关闭 / 路由器发现关闭 /
    //        无状态配置关闭 / NlMtu=MTU / AutoRoute 时 Metric=0；IPv4 开转发）──
    if let Some(luid) = if_luid {
        if has_v4 {
            if let Err(e) = win32_route::configure_interface(luid, AF_INET, cfg.mtu, true, true) {
                warn!(err = %e, "tun: configure IPv4 interface failed");
            }
        }
        if has_v6 {
            if let Err(e) = win32_route::configure_interface(luid, AF_INET6, cfg.mtu, true, false) {
                warn!(err = %e, "tun: configure IPv6 interface failed");
            }
        }
    }

    // ── 3. 接口 DNS（对齐 sing-tun configure()：DNS = server addr；禁 DNS 注册）──
    // 修复 M1：旧实现从不设置 TUN 接口 DNS，auto_route 后系统 DNS 查询进 TUN 无应答。
    if let Some(idx) = if_index {
        let mut dns_servers: Vec<IpAddr> = Vec::new();
        if has_v4 {
            if let Some(ip) = server_addr_v4(cfg) {
                dns_servers.push(IpAddr::V4(ip));
            }
        }
        if has_v6 {
            if let Some(ip) = server_addr_v6(cfg) {
                dns_servers.push(IpAddr::V6(ip));
            }
        }
        if !dns_servers.is_empty() {
            if let Err(e) = win32_route::set_interface_dns(idx, &dns_servers) {
                // Win32 SetInterfaceDnsSettings 对 wintun 接口偶发 E_INVALIDARG
                // （0x80070057，接口 GUID/版本不匹配），用 PowerShell
                // Set-DnsClientServerAddress 兜底（clash-rs 同款做法）。
                warn!(err = %e, "tun: set interface DNS via Win32 failed, trying PowerShell");
                let addrs = dns_servers
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let ok = Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &format!(
                            "Set-DnsClientServerAddress -InterfaceIndex {idx} \
                             -ServerAddresses ('{addrs}' -split ',') -ErrorAction Stop"
                        ),
                    ])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    warn!(
                        interface = %if_name,
                        "tun: failed to set interface DNS (Win32 + PowerShell)"
                    );
                }
            }
        }
        if let Err(e) = win32_route::disable_dns_registration(idx) {
            warn!(err = %e, "tun: disable DNS registration failed");
        }
    }

    // ── 4. auto_route 路由（metric=0，NextHop=网关，对齐 sing-tun addRouteList）──
    add_auto_routes(cfg, if_name, if_luid, if_index, has_v4, has_v6, &mut state);

    // ── 5. route_exclude_address（NextHop=物理网关 metric=0；B3 修复）────────
    add_exclude_routes(cfg, if_name, if_luid, if_index, has_v4, has_v6, &mut state);

    // ── 6. strict_route：完整 WFP 会话（对齐 sing-tun Start()）───────────────
    // 修复 B2：旧实现 WFP 过滤器缺 subLayerKey 导致添加失败且无自身进程/TUN permit。
    if cfg.strict_route {
        // 清理旧版本遗留的 netsh advfirewall 规则（新实现全部走 WFP）
        for name in LEGACY_STRICT_RULE_NAMES {
            Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={name}"),
                ])
                .output()
                .ok();
        }
        state.wfp_session =
            wfp::create_strict_session(current_exe_path(), if_index, has_v4, has_v6);
    }

    // 刷新 DNS 缓存
    Command::new("ipconfig").args(["/flushdns"]).output().ok();

    info!(interface = %if_name, "tun: auto_route configured (Windows)");
    Ok(state)
}

fn remove_reflex_bypass() {
    let if_idx: Option<u32> = (|| {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex",
            ])
            .output()
            .ok()?;
        let val = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
        Some(val)
    })();

    if let Some(if_idx) = if_idx {
        let reflex_ip: Option<String> = (|| {
            let out = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-NetIPAddress -InterfaceIndex {if_idx} -AddressFamily IPv4 \
                              -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress"
                    ),
                ])
                .output()
                .ok()?;
            let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if ip.is_empty() {
                None
            } else {
                Some(ip)
            }
        })();

        if let Some(reflex_ip) = reflex_ip {
            let out = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &format!("{reflex_ip}/32"),
                    &if_idx.to_string(),
                ])
                .output();
            let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
            if ok {
                info!(reflex_ip = %reflex_ip, "tun: removed reflex bypass route");
            } else {
                let stderr = out
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_default();
                warn!(reflex_ip = %reflex_ip, stderr = %stderr,
                      "tun: failed to remove reflex bypass route (may be already gone)");
            }
        }
    }
}

pub fn teardown(cfg: &TunInboundConfig, if_name: &str, state: &SetupState) -> anyhow::Result<()> {
    let if_index = win32_route::get_if_index(if_name);
    let if_luid = win32_route::get_interface_luid(if_name);

    // 清理 reflex bypass 路由
    remove_reflex_bypass();

    // 清理 auto_route 路由（DeleteIpForwardEntry2 的 key 含 NextHop，
    // 必须与创建时一致：auto 路由 NextHop=server addr，exclude 路由 NextHop=物理网关）
    let gw_v4 = server_addr_v4(cfg).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let gw_v6 = server_addr_v6(cfg).unwrap_or(Ipv6Addr::UNSPECIFIED);
    for cidr in &state.routes_v4 {
        let win32_ok = if let (Some(l), Some((dest, pl))) = (if_luid, parse_cidr_v4(cidr)) {
            win32_route::delete_route_v4(Some(l), if_index, dest, pl, gw_v4).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }
    for cidr in &state.routes_v6 {
        let win32_ok = if let (Some(l), Some((dest, pl))) = (if_luid, parse_cidr_v6(cidr)) {
            win32_route::delete_route_v6(Some(l), if_index, dest, pl, gw_v6).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }

    // 清理 exclude 路由（修复 B3：旧实现删除命令缺 interface 参数，永远删不掉）
    let gw_phys_v4 = get_default_gateway_v4();
    let gw_phys_v6 = get_default_gateway_v6();
    for cidr in &state.exclude_routes_v4 {
        let win32_ok = if let (Some(l), Some(gw), Some((dest, pl))) =
            (if_luid, gw_phys_v4, parse_cidr_v4(cidr))
        {
            win32_route::delete_route_v4(Some(l), if_index, dest, pl, gw).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }
    for cidr in &state.exclude_routes_v6 {
        let win32_ok = if let (Some(l), Some(gw), Some((dest, pl))) =
            (if_luid, gw_phys_v6, parse_cidr_v6(cidr))
        {
            win32_route::delete_route_v6(Some(l), if_index, dest, pl, gw).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }

    // 清理防火墙规则
    if cfg.strict_route {
        // 释放 WFP 会话（会话 drop 时通过 DYNAMIC 标志自动移除所有过滤器）
        if state.wfp_session != 0 {
            unsafe { wfp::drop_wfp_session(state.wfp_session) };
        }
        // 兼容旧版本 netsh 规则名清除
        for name in LEGACY_STRICT_RULE_NAMES {
            Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={name}"),
                ])
                .output()
                .ok();
        }
    }

    Command::new("ipconfig").args(["/flushdns"]).output().ok();
    info!(interface = %if_name, "tun: auto_route cleaned up (Windows)");
    Ok(())
}
