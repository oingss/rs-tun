use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
};
use tracing::{info, warn};

use super::super::packages_android::PackageManager;
use super::SetupState;
use crate::config::TunInboundConfig;

const ANDROID_USER_RANGE: u32 = 100000;
const PROTECTED_FROM_VPN_MARK: u32 = 0x20000;

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

fn v4_network(ip: Ipv4Addr, pl: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & !((1u32 << (32 - pl.min(32))) - 1))
}

// ── Netlink 禁止检测 ──────────────────────────────────────────────────────────
// Android 11+ 不允许非系统应用打开 netlink 套接字。

fn check_netlink_banned() -> bool {
    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE) };
    if sock < 0 {
        return true;
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    let ret = unsafe {
        libc::bind(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    unsafe {
        libc::close(sock);
    }
    ret < 0
}

// ── 路由计算 ──────────────────────────────────────────────────────────────────

fn route_v4(cfg: &TunInboundConfig) -> Vec<(Ipv4Addr, u8)> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        vec![(Ipv4Addr::UNSPECIFIED, 0)]
    }
}

fn route_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        vec![(Ipv6Addr::UNSPECIFIED, 0)]
    }
}

// ── UID / Android 用户 / 包名 → 排除范围 ─────────────────────────────────────

/// 构建 Android UID 排除范围集。
/// 处理 include_android_user、include_package、exclude_package 以及
/// 原有的 include_uid/exclude_uid/include_uid_range/exclude_uid_range。
async fn build_android_uid_exclusions(
    cfg: &TunInboundConfig,
    pkg_mgr: &PackageManager,
) -> Vec<(u32, u32)> {
    let mut excluded: Vec<(u32, u32)> = vec![];

    // 1. 处理 include_android_user：所包含用户之外的 UID 范围均应排除。
    //    Android 多用户机制：每个用户对应一个 UID 空间 [user_id * 100000, (user_id+1)*100000 - 1]
    //    - user 0：主用户（UIDs 0-99999）
    //    - user 10：工作配置（UIDs 1000000-1099999）
    //    - user 999：受限用户
    //    配置中可指定 user id（如 [0, 10]），仅这些用户的流量进入 TUN。
    let mut include_users: Vec<u32> = cfg
        .include_android_user
        .iter()
        .filter_map(|&u| {
            if u < 0 {
                warn!(
                    user_id = u,
                    "tun: ignoring negative include_android_user id"
                );
                None
            } else {
                Some(u as u32)
            }
        })
        .collect();
    if include_users.is_empty() {
        // 自动发现 /data/user/ 中的用户目录（包含主用户 0、工作配置 10 等）
        if let Ok(entries) = std::fs::read_dir("/data/user") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(uid) = name.parse::<u32>() {
                        include_users.push(uid);
                    }
                }
            }
        }
        if include_users.is_empty() {
            include_users.push(0); // 默认 owner 用户
        }
    }
    // 包含用户的 UID 空间为 [uid * 100000, (uid+1) * 100000 - 1]
    let mut include_ranges: Vec<(u32, u32)> = include_users
        .iter()
        .map(|&u| (u * ANDROID_USER_RANGE, (u + 1) * ANDROID_USER_RANGE - 1))
        .collect();
    include_ranges.sort_unstable();
    // 取补集作为排除范围
    let user_end = 999999; // 最大 Android UID
    excluded.extend(complement_ranges(&include_ranges, 0, user_end));

    // 2. 处理 include_package / exclude_package
    let include_uids: Vec<u32> = pkg_mgr.resolve_packages(&cfg.include_package).await;
    let exclude_uids: Vec<u32> = pkg_mgr.resolve_packages(&cfg.exclude_package).await;

    // 将 include_package 的 UID 从排除列表中移除
    for uid in &include_uids {
        excluded.retain(|(lo, hi)| !(*lo <= *uid && *uid <= *hi));
    }
    // 将 exclude_package 的 UID 加入排除列表
    for uid in &exclude_uids {
        excluded.push((*uid, *uid));
    }

    // 3. 合并原有的 include_uid / exclude_uid / include_uid_range / exclude_uid_range
    let inc_uids = merge_uid_list_and_ranges(&cfg.include_uid, &cfg.include_uid_range);
    let exc_uids = merge_uid_list_and_ranges(&cfg.exclude_uid, &cfg.exclude_uid_range);
    // include_uid 范围需要从排除集中移除
    for (lo, hi) in &inc_uids {
        excluded.retain(|(e_lo, e_hi)| !(*lo <= *e_lo && *hi >= *e_hi));
    }
    for uid in &exc_uids {
        excluded.push(*uid);
    }

    merge_ranges(excluded)
}

fn merge_uid_list_and_ranges(uids: &[u32], ranges: &[String]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = uids.iter().map(|&u| (u, u)).collect();
    for r in ranges {
        if let Some((lo, hi)) = parse_uid_range(r) {
            out.push((lo, hi));
        }
    }
    out.sort_unstable();
    out.dedup();
    merge_ranges(out)
}

fn parse_uid_range(s: &str) -> Option<(u32, u32)> {
    let (start_str, end_str) = s.split_once(':')?;
    let start: u32 = start_str.trim().parse().ok()?;
    let end: u32 = end_str.trim().parse().ok()?;
    if start > end {
        return None;
    }
    Some((start, end))
}

fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = vec![ranges[0]];
    for &(a, b) in &ranges[1..] {
        let last = merged.last_mut().unwrap();
        if a <= last.1.saturating_add(1) {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    merged
}

fn complement_ranges(ranges: &[(u32, u32)], start: u32, end: u32) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return vec![(start, end)];
    }
    let mut result = Vec::new();
    let mut cur = start;
    for &(lo, hi) in ranges {
        if cur < lo {
            result.push((cur, lo - 1));
        }
        cur = hi.saturating_add(1);
        if cur > end {
            break;
        }
    }
    if cur <= end {
        result.push((cur, end));
    }
    result
}

// ── 接口名解析（Android 需要查找 utun 接口）───────────────────────────────────

pub fn resolve_tun_interface(expected: &str) -> String {
    let path = format!("/dev/tun");
    if std::path::Path::new(&path).exists() {
        // Android TUN 设备始终为 /dev/tun，但接口名需通过 ifconfig 确认。
        let out = Command::new("ip")
            .args(["link", "show", expected])
            .output()
            .ok();
        if let Some(out) = out {
            if out.status.success() {
                return expected.to_string();
            }
        }
        // 尝试查找第一个 utun 接口
        let out = Command::new("ip")
            .args(["link", "show", "type", "tun"])
            .output()
            .ok();
        if let Some(out) = out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some(name) = line.trim().strip_suffix(':') {
                    let name = name.trim();
                    if name.starts_with("tun") || name.starts_with("utun") {
                        return name.to_string();
                    }
                }
            }
        }
    }
    expected.to_string()
}

// ── setup / teardown ──────────────────────────────────────────────────────────

pub async fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    // 检测 netlink 是否被禁止
    if check_netlink_banned() {
        warn!("tun: netlink socket banned on this Android device, some features limited");
    }

    let mut state = SetupState::default();
    let has_v4 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a)
            .map(|(ip, _)| ip.is_ipv4())
            .unwrap_or(false)
    });
    let has_v6 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a)
            .map(|(ip, _)| ip.is_ipv6())
            .unwrap_or(false)
    });

    // 启动包管理器
    let pkg_mgr = {
        let mut pm = PackageManager::new();
        let _ = pm.start().await;
        pm
    };

    // 构建 UID 排除
    let excluded_uids = build_android_uid_exclusions(cfg, &pkg_mgr).await;

    // 确保设备 UP
    Command::new("ip")
        .args(["link", "set", if_name, "up"])
        .output()
        .ok();

    // ── 路由表：TUN 子网走 TUN 接口 ────────────────────────────────────────
    // Android 不使用独立路由表 + 策略规则，而是通过 ip route add 直接添加。
    if has_v4 {
        for (net_ip, pl) in &route_v4(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("ip")
                .args(["route", "add", &cidr, "dev", if_name])
                .output()
                .ok();
            state.routes_v4.push(cidr);
        }
    }
    if has_v6 {
        for (net_ip, pl) in &route_v6(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("ip")
                .args(["-6", "route", "add", &cidr, "dev", if_name])
                .output()
                .ok();
            state.routes_v6.push(cidr);
        }
    }

    // ── 策略规则（简化：Android 不支持 suppress_prefixlength 和 dport 53）─
    let prio_base = cfg.iproute2_rule_index;
    let nop_prio = prio_base + 100;

    // UID 排除
    for (lo, hi) in &excluded_uids {
        if has_v4 {
            Command::new("ip")
                .args([
                    "rule",
                    "add",
                    "priority",
                    &prio_base.to_string(),
                    "uidrange",
                    &format!("{lo}-{hi}"),
                    "goto",
                    &nop_prio.to_string(),
                ])
                .output()
                .ok();
            state.rule_priorities.push(prio_base);
        }
    }

    // 接口过滤
    if !cfg.include_interface.is_empty() {
        for iface in &cfg.include_interface {
            if has_v4 {
                Command::new("ip")
                    .args([
                        "rule",
                        "add",
                        "priority",
                        &prio_base.to_string(),
                        "iif",
                        iface,
                        "lookup",
                        "main",
                    ])
                    .output()
                    .ok();
                state.rule_priorities.push(prio_base);
            }
        }
    } else if !cfg.exclude_interface.is_empty() {
        for iface in &cfg.exclude_interface {
            if has_v4 {
                Command::new("ip")
                    .args([
                        "rule",
                        "add",
                        "priority",
                        &prio_base.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &nop_prio.to_string(),
                    ])
                    .output()
                    .ok();
                state.rule_priorities.push(prio_base);
            }
        }
    }

    // ── Android VPN 0x20000 mark 旁路规则 ──────────────────────────────────
    // Android 的 VpnService.protect(socket) 会给 socket 打上 fwmark 0x20000
    // （PROTECTED_FROM_VPN_MARK），使其绕过 TUN/VPN。被保护的应用（如系统
    // 应用、被 VPN allowlist 的应用）调用 protect() 后流量需走 main 表。
    //
    // 对齐 sing-box route_android.go：
    // - 始终添加规则（不依赖 VPN 当前是否启用，因为应用随时可能调用 protect()）
    // - fwmark 以 `0x` 前缀的十六进制传递给 ip 命令（否则会被当作十进制解析）
    // - override_android_vpn=true 时附加 suppress_prefixlength 0：
    //     仍允许 TUN 的更具体路由覆盖 main 表的默认路由，
    //     即"接管"被保护应用的流量（仅当 TUN 有比默认更具体的路由时）
    // - v4/v6 双栈均添加
    let vpn_active = check_android_vpn_active();
    if vpn_active {
        info!("tun: Android system VPN detected, adding fwmark 0x20000 bypass rules");
    } else {
        info!("tun: adding fwmark 0x20000 bypass rules (for VpnService.protect() callers)");
    }
    let fwmark = format!("0x{PROTECTED_FROM_VPN_MARK:x}");
    for family in [None, Some("-6")] {
        let family_enabled = match family {
            None => has_v4,
            Some(_) => has_v6,
        };
        if !family_enabled {
            continue;
        }
        let mut rule = Command::new("ip");
        if let Some(arg) = family {
            rule.arg(arg);
        }
        rule.args([
            "rule",
            "add",
            "priority",
            &prio_base.to_string(),
            "fwmark",
            &fwmark,
            "lookup",
            "main",
        ]);
        if cfg.override_android_vpn {
            // suppress_prefixlength 0：抑制默认路由（prefixlen 0），
            // 仅当 main 表中有比 0 更具体的路由时才使用 main 表。
            // 这允许 TUN 接管被保护应用的流量（除非它们的目标有更具体的物理路由）。
            rule.arg("suppress_prefixlength").arg("0");
        }
        // 重复添加会失败（File exists），用 .ok() 忽略
        rule.output().ok();
        state.rule_priorities.push(prio_base);
    }

    // TUN 自身出站 → goto nop
    if has_v4 {
        Command::new("ip")
            .args([
                "rule",
                "add",
                "priority",
                &prio_base.to_string(),
                "iif",
                if_name,
                "goto",
                &nop_prio.to_string(),
            ])
            .output()
            .ok();
        state.rule_priorities.push(prio_base);
    }

    // 非 lo 出站 → lookup main
    if has_v4 {
        Command::new("ip")
            .args([
                "rule",
                "add",
                "priority",
                &prio_base.to_string(),
                "not",
                "iif",
                "lo",
                "lookup",
                "main",
            ])
            .output()
            .ok();
        state.rule_priorities.push(prio_base);
    }

    // lo src <tun_prefix> → lookup main
    for addr_str in &cfg.address {
        if let Some((IpAddr::V4(ip), pl)) = parse_addr_prefix(addr_str) {
            let net = v4_network(ip, pl);
            Command::new("ip")
                .args([
                    "rule",
                    "add",
                    "priority",
                    &prio_base.to_string(),
                    "iif",
                    "lo",
                    "from",
                    &format!("{net}/{pl}"),
                    "lookup",
                    "main",
                ])
                .output()
                .ok();
            state.rule_priorities.push(prio_base);
        }
    }

    // nop 锚点
    if has_v4 {
        Command::new("ip")
            .args(["rule", "add", "priority", &nop_prio.to_string()])
            .output()
            .ok();
    }

    info!(interface = %if_name, "tun: auto_route configured (Android)");
    Ok(state)
}

pub async fn teardown(
    cfg: &TunInboundConfig,
    if_name: &str,
    state: &SetupState,
) -> anyhow::Result<()> {
    // 清理路由
    for cidr in &state.routes_v4 {
        Command::new("ip")
            .args(["route", "del", cidr])
            .output()
            .ok();
    }
    for cidr in &state.routes_v6 {
        Command::new("ip")
            .args(["-6", "route", "del", cidr])
            .output()
            .ok();
    }

    // 清理规则
    for prio in &state.rule_priorities {
        Command::new("ip")
            .args(["rule", "del", "priority", &prio.to_string()])
            .output()
            .ok();
    }
    let nop_prio = cfg.iproute2_rule_index + 100;
    Command::new("ip")
        .args(["rule", "del", "priority", &nop_prio.to_string()])
        .output()
        .ok();

    info!(interface = %if_name, "tun: auto_route cleaned up (Android)");
    Ok(())
}

// ── Android VPN 检测 ──────────────────────────────────────────────────────────
// 通过读取 netlink 规则中 0x20000 mark 判断系统 VPN 是否启用。
// Android VpnService 启用时会自动添加 `fwmark 0x20000 lookup <table>` 规则。

fn check_android_vpn_active() -> bool {
    let out = Command::new("ip").args(["rule", "show"]).output().ok();
    let stdout = match out {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return false,
    };
    // `ip rule show` 输出中 fwmark 以 `0x20000` 形式显示（iproute2 默认十六进制）
    // 兼容两种格式：`fwmark 0x20000` 和 `fwmark 20000`（某些旧版本）
    let hex_mark = format!("0x{PROTECTED_FROM_VPN_MARK:x}");
    let dec_mark = format!("{}", PROTECTED_FROM_VPN_MARK);
    stdout.lines().any(|line| {
        line.contains("fwmark") && (line.contains(&hex_mark) || line.contains(&dec_mark))
    })
}
