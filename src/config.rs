//! TUN 入站配置。
//!
//! 从 reflex 主项目 `src/config/inbound.rs` 中原样提取，
//! 除去掉与其它入站类型共享的 derive 依赖外未做任何逻辑改动。

use serde::{Deserialize, Serialize};

/// TUN 虚拟网卡入站配置。
///
/// 创建一个 TUN 设备，从 L3 层截获所有经过该网卡的 IP 流量（TCP + UDP），
/// 解析出目标地址后交给路由层，无需 iptables/nftables 配合。
///
/// ## 平台支持矩阵
///
/// | 字段                  | Linux | macOS | Windows |
/// |-----------------------|-------|-------|---------|
/// | auto_route            | ✓     | ✓     | ✓       |
/// | iproute2_table_index  | ✓     | —     | —       |
/// | iproute2_rule_index   | ✓     | —     | —       |
/// | strict_route          | ✓     | —     | ✓ (WFP) |
/// | include_interface     | ✓     | —     | —       |
/// | exclude_interface     | ✓     | —     | —       |
/// | include_uid           | ✓     | —     | —       |
/// | exclude_uid           | ✓     | —     | —       |
/// | udp_timeout           | ✓     | ✓     | ✓       |
///
/// ## 典型用法
/// ```json
/// {
///   "type": "tun",
///   "tag": "tun-in",
///   "interface_name": "tun0",
///   "address": ["198.18.0.1/16", "fd00::1/126"],
///   "mtu": 9000,
///   "auto_route": true,
///   "strict_route": true,
///   "stack": "system"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunInboundConfig {
    /// 入站标识，用于路由规则匹配
    pub tag: String,

    /// TUN 设备名，留空则由系统自动分配
    /// Linux: `tun0`，macOS: `utun<N>`，Windows: 由 WinTun 分配
    #[serde(default)]
    pub interface_name: Option<String>,

    /// TUN 设备 MTU，默认 9000
    #[serde(default = "default_tun_mtu")]
    pub mtu: u32,

    /// TUN 设备绑定的 IPv4/IPv6 地址前缀列表
    /// 例如 `["198.18.0.1/16", "fd00::1/126"]`，至少需要一个 IPv4 前缀。
    /// 网关地址由第一个前缀自动推导（Linux/Windows 取下一个 IP，macOS 取自身）。
    pub address: Vec<String>,

    /// 是否自动配置系统路由，将默认流量导入 TUN 设备。
    ///
    /// - **Linux**：在独立路由表（`iproute2_table_index`，默认 2022）中添加路由，
    ///   通过策略规则（`iproute2_rule_index`，默认优先级 9000）引导流量；
    ///   自身出站流量通过 fwmark / `iif lo` 规则绕过，避免环回。
    /// - **macOS**：通过 `AF_ROUTE` socket（`RTM_ADD`）添加路由条目。
    /// - **Windows**：通过 `CreateIpForwardEntry2` WinAPI 添加路由。
    #[serde(default)]
    pub auto_route: bool,

    /// Linux 专用：`auto_route` 使用的 iproute2 路由表编号，默认 2022。
    /// 不同实例需使用不同的表编号以避免冲突。
    #[serde(default = "default_iproute2_table_index")]
    pub iproute2_table_index: u32,

    /// Linux 专用：`auto_route` 策略规则起始优先级，默认 9000。
    /// 规则集实际占用的槽位数量取决于配置（UID 规则数、接口规则数、地址数等），
    /// 建议预留至少 200 个优先级槽位（即不要在 `[priority, priority+200)` 内放其他规则）。
    /// nop 锚点固定在 `priority + 100`，teardown 时根据 setup 记录的状态精确清理。
    #[serde(default = "default_iproute2_rule_index")]
    pub iproute2_rule_index: u32,

    /// Linux 专用：出站 socket 的 fwmark 值。
    /// 设置后 reflex 自身出站流量会带上此 mark，路由规则可据此绕过 TUN，
    /// 避免路由循环。与 clash-rs 的 `so_mark` 配置项一致。
    /// 默认不设置（None）。
    #[serde(default)]
    pub so_mark: Option<u32>,

    /// 严格路由模式，需配合 `auto_route`。
    ///
    /// - **Linux**：为缺失地址族（无 IPv4 或无 IPv6 地址时）添加
    ///   `FR_ACT_UNREACHABLE` 规则，阻止不支持的协议流量绕过 TUN。
    /// - **Windows**：通过 WFP（Windows Filtering Platform）阻止非 TUN
    ///   接口的 DNS（53 端口）流量，防止多宿主 DNS 泄漏。
    ///   （需要 Windows 10 及以上；更低版本会打印警告并跳过）
    /// - **macOS**：无效果，macOS 无对应内核机制。
    #[serde(default)]
    pub strict_route: bool,

    /// 网络栈实现：
    /// - `"system"`（默认）：依赖内核网络栈进行 L3→L4 转换，性能最佳
    /// - `"gvisor"`：用户态 gVisor 协议栈，兼容性更强
    /// - `"mixed"`：TCP 用 system，UDP 用 gVisor
    #[serde(default = "default_tun_stack")]
    pub stack: String,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截来自这些网络接口的流量，留空表示全部接口。
    /// 通过 `ip rule add iif <iface> goto <table_rule>` 实现白名单。
    /// 与 `exclude_interface` 互斥。
    #[serde(default)]
    pub include_interface: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除来自这些网络接口的流量。
    /// 通过 `ip rule add iif <iface> goto <nop>` 跳过 TUN 路由实现。
    /// 与 `include_interface` 互斥。
    #[serde(default)]
    pub exclude_interface: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截属于这些 UID 的流量，留空表示全部用户。
    /// 实现方式：先为指定 UID 建立包含规则，再将其余所有 UID 范围
    /// 通过 `ip rule add uidrange ... goto <nop>` 排除。
    #[serde(default)]
    pub include_uid: Vec<u32>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除属于这些 UID 的流量。
    /// 通过 `ip rule add uidrange <uid>-<uid> goto <nop>` 实现。
    #[serde(default)]
    pub exclude_uid: Vec<u32>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截这些 UID 范围的流量，使用 `"start:end"` 字符串形式（与 sing-box 一致）。
    /// 例如 `["1000:2000"]` 表示拦截 UID 1000-2000。
    /// 与 `include_uid` 叠加；解析后与 `include_uid` 合并。
    #[serde(default)]
    pub include_uid_range: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除这些 UID 范围的流量，使用 `"start:end"` 字符串形式（与 sing-box 一致）。
    /// 例如 `["0:999"]` 表示排除 UID 0-999。
    /// 与 `exclude_uid` 叠加；解析后与 `exclude_uid` 合并。
    #[serde(default)]
    pub exclude_uid_range: Vec<String>,

    /// **所有平台**（需要 `auto_route`）：
    /// 仅将指定 CIDR 范围的流量导入 TUN（与 sing-box `route_address` 一致）。
    /// 留空表示劫持默认路由（`0.0.0.0/0` 和 `::/0`）。
    /// 例如 `["1.1.1.0/24", "8.8.8.0/24"]` 表示只代理这两个网段。
    #[serde(default)]
    pub route_address: Vec<String>,

    /// **所有平台**（需要 `auto_route`）：
    /// 排除指定 CIDR 范围的流量不导入 TUN（与 sing-box `route_exclude_address` 一致）。
    /// 优先级高于 `route_address` 和默认劫持。
    /// 例如 `["192.168.0.0/16"]` 表示排除局域网。
    #[serde(default)]
    pub route_exclude_address: Vec<String>,

    /// **所有平台**：
    /// 用于 acceptLoop 中目标重写的 loopback 地址（与 sing-box `loopback_address` 一致）。
    /// 默认为 `127.0.0.1` 和 `::1`。
    /// 若指定，必须同时给出 IPv4 和 IPv6 地址（或仅给出需要的地址族）。
    #[serde(default)]
    pub loopback_address: Vec<String>,

    /// UDP NAT 会话超时（秒），0 表示使用默认值 300 秒。
    #[serde(default)]
    pub udp_timeout: u64,

    /// TCP MSS clamping 上限（参照 sing-tun `clampTCPMSS`）。
    ///
    /// 设为 `Some(mss)` 后，所有经过 TUN 的 TCP SYN / SYN-ACK 包中
    /// MSS option 会被改写为 `min(原值, mss)`，避免 PMTUD 黑洞。
    /// 未配置（`None`）时不做 MSS 改写，保留原包。
    ///
    /// 常见取值：
    /// - `1452`：MTU 1492（PPPoE）下常用
    /// - `1400`：MTU 1440（VPN / WireGuard 默认）下常用
    /// - `1280`：IPv6 最小 MTU 1280 对应的 MSS
    #[serde(default)]
    pub tcp_mss: Option<u16>,

    // ── Android 专用 ──────────────────────────────────────────────────────────
    /// **Android 专用**：要包含的 Android 用户 ID 列表。
    /// 每个用户对应一个完整的 UID 空间（user_id * 100000）。
    /// 留空时自动枚举 `/data/user/` 目录。
    #[serde(default)]
    pub include_android_user: Vec<i32>,

    /// **Android 专用**：将指定的 Android 包名转为其 UID 后加入包含列表。
    /// 解析 `/data/system/packages.xml` 获取包名到 UID 的映射。
    #[serde(default)]
    pub include_package: Vec<String>,

    /// **Android 专用**：将指定的 Android 包名转为其 UID 后加入排除列表。
    #[serde(default)]
    pub exclude_package: Vec<String>,

    /// **Android 专用**：是否覆盖系统 VPN 检测。
    /// 当系统 VPN 启用时，reflex 默认会创建规则绕过系统 VPN。
    /// 设为 true 后，reflex 接管系统 VPN 的流量。
    #[serde(default)]
    pub override_android_vpn: bool,

    // ── Linux auto_redirect (nftables TPROXY) ──────────────────────────────
    /// **Linux 专用**：自动配置 nftables TPROXY 规则重定向流量到 TUN。
    ///
    /// 启用后，reflex 会在 setup 阶段通过 `nft` 命令创建 nftables 表和链：
    /// - `mangle` 表的 `PREROUTING` 链：对入站 TCP/UDP 包打 input_mark
    /// - `mangle` 表的 `OUTPUT` 链：对 reflex 自身出站包打 output_mark（绕过 TPROXY）
    /// - `ip rule fwmark <input_mark> lookup <table>`：将打了 mark 的包路由到 TUN
    ///
    /// 适用于 TUN 无法捕获某些流量（如 Docker 容器流量）的场景。
    /// 对齐 sing-tun `auto_redirect` 功能。
    #[serde(default)]
    pub auto_redirect: bool,

    /// **Linux 专用**：auto_redirect 入站 fwmark 值。
    /// 默认 `0x2022`（与 iproute2_table_index 关联）。
    /// 此 mark 被打到入站包上，触发 `ip rule fwmark` 规则路由到 TUN 表。
    #[serde(default = "default_auto_redirect_input_mark")]
    pub auto_redirect_input_mark: u32,

    /// **Linux 专用**：auto_redirect 出站 fwmark 值。
    /// 默认 `0x3022`。reflex 自身出站 socket 设置此 mark，
    /// `nft OUTPUT` 链根据此 mark 跳过 TPROXY，避免路由循环。
    #[serde(default = "default_auto_redirect_output_mark")]
    pub auto_redirect_output_mark: u32,
}

fn default_auto_redirect_input_mark() -> u32 {
    0x2022
}

fn default_auto_redirect_output_mark() -> u32 {
    0x3022
}

fn default_tun_mtu() -> u32 {
    9000
}

fn default_tun_stack() -> String {
    "system".to_string()
}

fn default_iproute2_table_index() -> u32 {
    2022
}

fn default_iproute2_rule_index() -> u32 {
    9000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小配置（只给必填字段）应能成功反序列化，且各默认值与
    /// reflex 主项目保持一致。
    #[test]
    fn minimal_config_round_trip() {
        let json = r#"{
            "tag": "tun-in",
            "address": ["198.18.0.1/16"]
        }"#;
        let cfg: TunInboundConfig = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(cfg.tag, "tun-in");
        assert_eq!(cfg.address, vec!["198.18.0.1/16".to_string()]);
        assert_eq!(cfg.mtu, 9000);
        assert_eq!(cfg.stack, "system");
        assert!(!cfg.auto_route);
        assert_eq!(cfg.iproute2_table_index, 2022);
        assert_eq!(cfg.iproute2_rule_index, 9000);
        assert_eq!(cfg.auto_redirect_input_mark, 0x2022);
        assert_eq!(cfg.auto_redirect_output_mark, 0x3022);
    }

    /// 显式指定的字段应覆盖默认值。
    #[test]
    fn explicit_fields_override_defaults() {
        let json = r#"{
            "tag": "tun-in",
            "address": ["198.18.0.1/16", "fd00::1/126"],
            "mtu": 1500,
            "auto_route": true,
            "stack": "gvisor",
            "strict_route": true
        }"#;
        let cfg: TunInboundConfig = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(cfg.mtu, 1500);
        assert!(cfg.auto_route);
        assert_eq!(cfg.stack, "gvisor");
        assert!(cfg.strict_route);
        assert_eq!(cfg.address.len(), 2);
    }

    /// 缺少必填字段（address）应反序列化失败。
    #[test]
    fn missing_required_field_fails() {
        let json = r#"{ "tag": "tun-in" }"#;
        let result: Result<TunInboundConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
