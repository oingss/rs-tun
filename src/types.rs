//! 与宿主代理项目交互的公共类型。
//!
//! 这些类型定义了 reflex-tun 与宿主项目（reflex 或其它 Rust 代理项目）之间的
//! 接口边界：TUN inbound 只产出 [`InboundTcpStream`] / [`InboundUdpPacket`]，
//! 具体路由 / 出站转发逻辑完全由宿主项目决定，本 crate 不关心。
//!
//! 类型定义与 reflex 主项目 `src/inbound/mod.rs` 中的同名类型保持一致，
//! 便于 reflex 主项目切换为依赖本 crate 时做无痛适配（字段一一对应）。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{mpsc, oneshot},
};

// ── Target ───────────────────────────────────────────────────────────────────

/// 连接目标：域名或 IP。
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Target {
    /// 域名 + 端口
    Domain(String, u16),
    /// IP + 端口
    Socket(SocketAddr),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) => *p,
            Self::Socket(a) => a.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(d, _) => d.clone(),
            Self::Socket(a) => a.ip().to_string(),
        }
    }

    /// 将 Target 转为 SocketAddr，Domain 类型使用 0.0.0.0 占位
    /// （仅用于回包伪造源地址场景）。
    pub fn to_socket_addr_lossy(&self) -> SocketAddr {
        match self {
            Self::Socket(a) => *a,
            Self::Domain(_, p) => SocketAddr::from(([0, 0, 0, 0], *p)),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(d, p) => write!(f, "{d}:{p}"),
            Self::Socket(a) => write!(f, "{a}"),
        }
    }
}

// ── SniffedStream ────────────────────────────────────────────────────────────

/// 对 [`TcpStream`] 的薄包装，允许在嗅探时将 peek 出的字节归还回去，
/// 使后续的读取对这些字节无感知。
///
/// 读取顺序：先消耗 `prefix`，再透传 `inner`。
/// 写入、关闭等操作直接委托给 `inner`。
pub struct SniffedStream {
    /// 嗅探阶段 peek 出的字节（未嗅探时为空）
    pub prefix: Bytes,
    pub inner: TcpStream,
    /// 实时流量计数器（可选）
    pub live_down: Option<std::sync::Arc<portable_atomic::AtomicI64>>,
    pub live_up: Option<std::sync::Arc<portable_atomic::AtomicI64>>,
    /// 缓存的 peer_addr：第一次调用 peer_addr() 成功后缓存，避免后续重复 syscall。
    peer_addr_cache: std::cell::OnceCell<std::net::SocketAddr>,
}

impl SniffedStream {
    /// 直接从裸 [`TcpStream`] 创建，prefix 为空（未嗅探）。
    pub fn new(stream: TcpStream) -> Self {
        Self {
            prefix: Bytes::new(),
            inner: stream,
            live_down: None,
            live_up: None,
            peer_addr_cache: std::cell::OnceCell::new(),
        }
    }

    /// 注入实时计数器，后续每次 read/write 都会更新对应原子值。
    pub fn set_live_counters(
        &mut self,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) {
        self.live_up = Some(live_up);
        self.live_down = Some(live_down);
    }

    /// 嗅探完成后，将 peek 出的字节作为 prefix 归还。
    pub fn prepend(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        if self.prefix.is_empty() {
            self.prefix = data;
        } else {
            let mut buf = bytes::BytesMut::with_capacity(self.prefix.len() + data.len());
            buf.extend_from_slice(&self.prefix);
            buf.extend_from_slice(&data);
            self.prefix = buf.freeze();
        }
    }

    /// 委托给内层 TcpStream 的 `peer_addr()`，首次成功调用后缓存结果。
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        if let Some(cached) = self.peer_addr_cache.get() {
            return Ok(*cached);
        }
        let addr = self.inner.peer_addr()?;
        let _ = self.peer_addr_cache.set(addr);
        Ok(addr)
    }
}

impl AsyncRead for SniffedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let amt = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..amt]);
            self.prefix.advance(amt);
            if let Some(c) = &self.live_down {
                c.fetch_add(amt as i64, std::sync::atomic::Ordering::Relaxed);
            }
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                if let Some(c) = &self.live_down {
                    c.fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        result
    }
}

impl AsyncWrite for SniffedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &result {
            if let Some(c) = &self.live_up {
                c.fetch_add(*n as i64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── InboundTcpStream ─────────────────────────────────────────────────────────

/// 一条已建立的入站 TCP 连接，携带原始目标地址。
/// 宿主项目的路由层拿到它后决定走哪个出站。
pub struct InboundTcpStream {
    /// TCP 流（可能携带嗅探时 peek 出的前缀字节）
    pub stream: SniffedStream,
    /// 连接的真实目标（域名或 IP:Port）
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None。
    /// TUN inbound 本身不做协议嗅探，此字段始终为 None，保留字段是为了
    /// 与宿主项目其它入站类型（socks/http/mixed 等）的结构体保持一致。
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名，同上，TUN inbound 恒为 None。
    pub sniffed_domain: Option<String>,
}

// ── UdpSession ───────────────────────────────────────────────────────────────

/// UDP 会话句柄，入站层持有，用于将出站的回包写回给客户端。
#[derive(Debug, Clone)]
pub struct UdpSession {
    /// 用于回包：(数据, 客户端地址, 伪造源地址=原始目标IP)
    pub reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
}

// ── InboundUdpPacket ─────────────────────────────────────────────────────────

/// 一个入站 UDP 数据包（或 UDP 会话的第一个包），携带原始目标地址。
pub struct InboundUdpPacket {
    /// 数据载荷
    pub data: Bytes,
    /// 发送方地址（用于回包）
    pub src: SocketAddr,
    /// 真实目标地址
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// TUN inbound 恒为 None，保留字段用于与宿主项目其它入站类型对齐。
    pub sniffed_protocol: Option<String>,
    pub sniffed_domain: Option<String>,
    /// 原始 FakeIP 目标地址（仅在宿主项目做 FakeIP 反向查找命中时被设置）。
    /// TUN inbound 自身不做 FakeIP 处理，此字段恒为 None；宿主项目的
    /// dispatcher 可在收到包后自行改写。
    pub origin_destination: Option<SocketAddr>,
    /// UDP 会话句柄（用于后续回包）
    pub session: UdpSession,
    /// 后续上行包通道（会话期间持续产出同一 (src, target) 会话的包）。
    /// 出站实现收到后应持续从此通道读取并发往服务端，直到通道关闭或超时，
    /// 这保证整个会话共用同一个出站 socket（固定源端口）。
    pub upstream_rx: Option<mpsc::Receiver<(Target, Bytes)>>,
    /// 需要与会话生命周期绑定的守卫对象，供宿主项目挂载自定义生命周期钩子
    /// （如连接数统计、API 可见性等）。TUN inbound 自身不产出任何守卫，
    /// 恒为空 Vec。
    pub lifetime_guards: Vec<Box<dyn std::any::Any + Send>>,
}

// ── DNS 劫持相关类型 ─────────────────────────────────────────────────────────

/// DNS 查询来源类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQuerySource {
    /// 来自专用 DNS 入站
    Inbound,
    /// 来自路由层 hijack_dns 规则（流量原本目标是 53 端口，被路由劫持）
    Hijacked,
}

/// 一次 DNS 查询请求，附带回复通道。
///
/// TUN inbound 在 `auto_route` + DNS 劫持场景下，会直接拦截目的端口 53 的
/// UDP 流量并构造 [`DnsQuery`] 发送给宿主项目的 DNS 解析器，而不经过常规的
/// [`InboundUdpPacket`] 路由路径（对齐 clash-rs / sing-box 的做法）。
#[derive(Debug)]
pub struct DnsQuery {
    /// 原始 DNS wire-format 查询报文
    pub message: Bytes,
    /// 查询来源地址（用于日志）
    pub from: SocketAddr,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 查询来源类型
    pub source: DnsQuerySource,
    /// 回复通道：DNS 解析器将 wire-format 响应写回此处
    pub reply_tx: oneshot::Sender<Bytes>,
}

/// 向 DNS 解析器发送查询的通道类型别名。
pub type DnsQueryTx = mpsc::Sender<DnsQuery>;
