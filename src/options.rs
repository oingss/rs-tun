//! sing-tun 风格的 `Options`。
//!
//! 字段基本与 sing-tun `tun.go` 中的 `Options` struct 一一对应（Go 的
//! `netip.Prefix` 对应这里的 [`Prefix`]，`netip.Addr` 对应 `std::net::IpAddr`），
//! 命名从 Go 的大驼峰改为 Rust 惯用的 snake_case。
//!
//! `TunInboundConfig`（[`crate::config::TunInboundConfig`]）是本 crate 面向
//! JSON 配置文件的入站配置层（类比 sing-box 的 `option.TunInboundOptions`），
//! `Options` 是真正驱动 TUN/协议栈的运行期选项（类比 sing-tun 的
//! `tun.Options`）。宿主项目可以：
//! - 从 JSON/自有配置反序列化出 `TunInboundConfig`，再用 [`TunInboundConfig::to_options`]
//!   转成 `Options`；也可以
//! - 完全不使用 `TunInboundConfig`，直接手工构造 `Options`（更贴近直接使用
//!   sing-tun 的体验）。

use std::net::IpAddr;

use crate::config::TunInboundConfig;

/// 对应 Go `netip.Prefix`：一个 IP 地址 + 前缀长度。
pub type Prefix = (IpAddr, u8);

/// UID 区间，闭区间 `[start, end]`，对应 sing-tun `ranges.Range[uint32]`。
pub type UidRange = (u32, u32);

/// 网络栈实现选择，对应 sing-tun `NewStack` 的 `stack string` 参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StackKind {
    /// 依赖内核网络栈做 L3→L4 转换，性能最佳。
    #[default]
    System,
    /// 用户态 gVisor 风格协议栈（本 crate 基于 smoltcp 实现），兼容性更强。
    Gvisor,
    /// TCP 走 system，UDP 走 gvisor 的混合模式。
    Mixed,
}

impl StackKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StackKind::System => "system",
            StackKind::Gvisor => "gvisor",
            StackKind::Mixed => "mixed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "" | "system" => Some(StackKind::System),
            "gvisor" => Some(StackKind::Gvisor),
            "mixed" => Some(StackKind::Mixed),
            _ => None,
        }
    }
}

/// sing-tun `tun.Options` 的 Rust 对应物。
///
/// 字段名与 Go 版基本对应（如 `Inet4Address` → `inet4_address`），只有
/// Linux-only 的策略路由参数保留了 `iproute2_*` 前缀以贴近原名。
#[derive(Debug, Clone)]
pub struct Options {
    /// 接口名，留空则由系统自动分配（对应 `Options.Name`）。
    pub name: Option<String>,
    pub inet4_address: Vec<Prefix>,
    pub inet6_address: Vec<Prefix>,
    pub mtu: u32,
    /// 是否启用 GSO/GRO 卸载（Linux `IFF_VNET_HDR`）。
    ///
    /// 注意：当前引擎（[`crate::tun::TunInbound`]）在设备创建时会自动探测内核
    /// 是否支持 TUNSETOFFLOAD，不读取这个字段——这里保留它只是为了和 sing-tun
    /// `Options.GSO` 的字段形状对齐，[`Options::to_config`] 目前不会把它写回
    /// [`TunInboundConfig`]。
    pub gso: bool,
    pub auto_route: bool,
    pub inet4_gateway: Option<IpAddr>,
    pub inet6_gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub iproute2_table_index: u32,
    pub iproute2_rule_index: u32,
    pub inet4_loopback_address: Vec<IpAddr>,
    pub inet6_loopback_address: Vec<IpAddr>,
    pub strict_route: bool,
    pub inet4_route_address: Vec<Prefix>,
    pub inet6_route_address: Vec<Prefix>,
    pub inet4_route_exclude_address: Vec<Prefix>,
    pub inet6_route_exclude_address: Vec<Prefix>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<UidRange>,
    pub exclude_uid: Vec<UidRange>,
    pub include_android_user: Vec<i32>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,

    /// TCP MSS clamping 上限，对应 sing-tun 内部 `clampTCPMSS`（sing-tun 本身
    /// 未直接在 `Options` 里暴露此字段，这里作为 reflex-tun 的扩展项保留）。
    pub tcp_mss: Option<u16>,
    /// UDP NAT 会话超时。
    pub udp_timeout: std::time::Duration,
    /// 使用哪种协议栈。
    pub stack: StackKind,

    /// Linux 专用：nftables TPROXY auto_redirect。
    pub auto_redirect: bool,
    pub auto_redirect_input_mark: u32,
    pub auto_redirect_output_mark: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            name: None,
            inet4_address: Vec::new(),
            inet6_address: Vec::new(),
            mtu: 9000,
            gso: false,
            auto_route: false,
            inet4_gateway: None,
            inet6_gateway: None,
            dns_servers: Vec::new(),
            iproute2_table_index: 2022,
            iproute2_rule_index: 9000,
            inet4_loopback_address: Vec::new(),
            inet6_loopback_address: Vec::new(),
            strict_route: false,
            inet4_route_address: Vec::new(),
            inet6_route_address: Vec::new(),
            inet4_route_exclude_address: Vec::new(),
            inet6_route_exclude_address: Vec::new(),
            include_interface: Vec::new(),
            exclude_interface: Vec::new(),
            include_uid: Vec::new(),
            exclude_uid: Vec::new(),
            include_android_user: Vec::new(),
            include_package: Vec::new(),
            exclude_package: Vec::new(),
            tcp_mss: None,
            udp_timeout: std::time::Duration::from_secs(300),
            stack: StackKind::System,
            auto_redirect: false,
            auto_redirect_input_mark: 0x2022,
            auto_redirect_output_mark: 0x3022,
        }
    }
}

fn parse_prefix(s: &str) -> Option<Prefix> {
    let (addr, plen) = s.split_once('/')?;
    Some((addr.parse().ok()?, plen.parse().ok()?))
}

fn parse_uid_range(s: &str) -> Option<UidRange> {
    match s.split_once(':') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => {
            let v = s.parse().ok()?;
            Some((v, v))
        }
    }
}

impl TunInboundConfig {
    /// 把 JSON 配置层转换为 sing-tun 风格的运行期 [`Options`]。
    ///
    /// 无法解析的字段（如非法 CIDR 字符串）会被跳过，而不是导致整体失败，
    /// 与引擎内部 `parse_addr_prefix` 的容错策略保持一致。
    pub fn to_options(&self) -> Options {
        let mut o = Options {
            name: self.interface_name.clone(),
            mtu: self.mtu,
            gso: true,
            auto_route: self.auto_route,
            iproute2_table_index: self.iproute2_table_index,
            iproute2_rule_index: self.iproute2_rule_index,
            strict_route: self.strict_route,
            include_interface: self.include_interface.clone(),
            exclude_interface: self.exclude_interface.clone(),
            include_android_user: self.include_android_user.clone(),
            include_package: self.include_package.clone(),
            exclude_package: self.exclude_package.clone(),
            tcp_mss: self.tcp_mss,
            udp_timeout: std::time::Duration::from_secs(if self.udp_timeout == 0 {
                300
            } else {
                self.udp_timeout
            }),
            stack: StackKind::parse(&self.stack).unwrap_or_default(),
            auto_redirect: self.auto_redirect,
            auto_redirect_input_mark: self.auto_redirect_input_mark,
            auto_redirect_output_mark: self.auto_redirect_output_mark,
            ..Options::default()
        };

        for a in &self.address {
            if let Some((addr, plen)) = parse_prefix(a) {
                match addr {
                    IpAddr::V4(_) => o.inet4_address.push((addr, plen)),
                    IpAddr::V6(_) => o.inet6_address.push((addr, plen)),
                }
            }
        }
        for a in &self.loopback_address {
            if let Ok(ip) = a.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(_) => o.inet4_loopback_address.push(ip),
                    IpAddr::V6(_) => o.inet6_loopback_address.push(ip),
                }
            }
        }
        for a in &self.route_address {
            if let Some((addr, plen)) = parse_prefix(a) {
                match addr {
                    IpAddr::V4(_) => o.inet4_route_address.push((addr, plen)),
                    IpAddr::V6(_) => o.inet6_route_address.push((addr, plen)),
                }
            }
        }
        for a in &self.route_exclude_address {
            if let Some((addr, plen)) = parse_prefix(a) {
                match addr {
                    IpAddr::V4(_) => o.inet4_route_exclude_address.push((addr, plen)),
                    IpAddr::V6(_) => o.inet6_route_exclude_address.push((addr, plen)),
                }
            }
        }
        o.include_uid = self
            .include_uid
            .iter()
            .map(|&u| (u, u))
            .chain(self.include_uid_range.iter().filter_map(|s| parse_uid_range(s)))
            .collect();
        o.exclude_uid = self
            .exclude_uid
            .iter()
            .map(|&u| (u, u))
            .chain(self.exclude_uid_range.iter().filter_map(|s| parse_uid_range(s)))
            .collect();

        o
    }
}

fn prefix_to_string((addr, plen): &Prefix) -> String {
    format!("{addr}/{plen}")
}

impl Options {
    /// [`TunInboundConfig::to_options`] 的反向转换：把运行期 [`Options`] 还原成
    /// JSON 配置层的 [`TunInboundConfig`]，供仍然基于 `TunInboundConfig` 驱动的
    /// 引擎内部复用（宿主项目一般不需要关心这一步，直接用 `Options` + [`crate::stack`]
    /// 提供的入口即可）。
    ///
    /// `tag` 对应 sing-tun `Options.Name` 之外、本 crate 引擎另外要求的入站标识。
    pub fn to_config(&self, tag: impl Into<String>) -> TunInboundConfig {
        let address = self
            .inet4_address
            .iter()
            .chain(self.inet6_address.iter())
            .map(prefix_to_string)
            .collect();
        let loopback_address = self
            .inet4_loopback_address
            .iter()
            .chain(self.inet6_loopback_address.iter())
            .map(|a| a.to_string())
            .collect();
        let route_address = self
            .inet4_route_address
            .iter()
            .chain(self.inet6_route_address.iter())
            .map(prefix_to_string)
            .collect();
        let route_exclude_address = self
            .inet4_route_exclude_address
            .iter()
            .chain(self.inet6_route_exclude_address.iter())
            .map(prefix_to_string)
            .collect();
        let include_uid_range = self
            .include_uid
            .iter()
            .map(|(a, b)| format!("{a}:{b}"))
            .collect();
        let exclude_uid_range = self
            .exclude_uid
            .iter()
            .map(|(a, b)| format!("{a}:{b}"))
            .collect();

        TunInboundConfig {
            tag: tag.into(),
            interface_name: self.name.clone(),
            mtu: self.mtu,
            address,
            auto_route: self.auto_route,
            iproute2_table_index: self.iproute2_table_index,
            iproute2_rule_index: self.iproute2_rule_index,
            so_mark: None,
            strict_route: self.strict_route,
            stack: self.stack.as_str().to_string(),
            include_interface: self.include_interface.clone(),
            exclude_interface: self.exclude_interface.clone(),
            include_uid: Vec::new(),
            exclude_uid: Vec::new(),
            include_uid_range,
            exclude_uid_range,
            route_address,
            route_exclude_address,
            loopback_address,
            udp_timeout: self.udp_timeout.as_secs(),
            tcp_mss: self.tcp_mss,
            include_android_user: self.include_android_user.clone(),
            include_package: self.include_package.clone(),
            exclude_package: self.exclude_package.clone(),
            override_android_vpn: false,
            auto_redirect: self.auto_redirect,
            auto_redirect_input_mark: self.auto_redirect_input_mark,
            auto_redirect_output_mark: self.auto_redirect_output_mark,
        }
    }
}
