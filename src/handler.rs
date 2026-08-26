//! sing-tun 风格的 `Handler` 接口。
//!
//! 对齐 sing-tun `tun.go` 中的：
//! ```go
//! type Handler interface {
//!     PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr) error
//!     N.TCPConnectionHandlerEx
//!     N.UDPConnectionHandlerEx
//! }
//! ```
//!
//! sing-tun 把「TUN 拆包/协议栈处理」和「拿到连接后做什么」拆成两层：
//! 协议栈只管把 L3 包还原成 TCP 连接 / UDP 包，然后回调 `Handler`；
//! 至于连接要不要走代理、走哪个出站，完全由 `Handler` 的实现者决定。
//!
//! 本 crate 原有的 `TunInbound` 是通过 `mpsc::Sender<InboundTcpStream>` /
//! `mpsc::Sender<InboundUdpPacket>` 产出连接的（更贴近 Rust 异步生态的习惯用法）。
//! 这里补一层 `Handler` trait，让调用方也可以按 sing-tun 的心智模型直接注入
//! 回调对象，而不必自己维护 channel；[`ChannelHandler`] 则反过来，把一个
//! `Handler` 适配成旧的 channel 消费方式，两种用法可以互转，互不冲突。

use std::sync::Arc;

use async_trait::async_trait;

use crate::types::{DnsQuery, DnsQueryTx, InboundTcpStream, InboundUdpPacket};

/// TUN 协议栈向宿主项目交付连接的回调接口。
///
/// 对应 sing-tun 的 `Handler`：`NewConnection` ≈ `new_connection`，
/// `NewPacketConnection` ≈ `new_packet`。`prepare_connection` 对应
/// `PrepareConnection`，用于在连接建立前做一次前置检查（例如按规则丢弃），
/// 默认实现直接放行。
///
/// 实现者通常只需要关心 `new_connection` / `new_packet`；DNS 劫持是本 crate
/// 相对于 sing-tun 的一个扩展点（sing-tun 里 DNS 劫持发生在宿主项目的路由层，
/// 这里额外暴露出来是因为 reflex 系的实现选择在 TUN 层面直接拦截），实现方不需要
/// DNS 劫持的话，用默认实现（不消费、交还给上层按普通 UDP 包处理）即可。
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// 连接建立前的准入检查（对应 sing-tun `PrepareConnection`）。
    /// 返回 `Err` 时协议栈会丢弃该连接尝试（等价于 sing-tun 的 `ErrDrop`）。
    async fn prepare_connection(
        &self,
        _network: Network,
        _source: std::net::SocketAddr,
        _destination: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// 一条 TUN 内新建立的 TCP 连接（对应 sing-tun `N.TCPConnectionHandlerEx.NewConnectionEx`）。
    async fn new_connection(&self, conn: InboundTcpStream);

    /// 一个 TUN 内新出现的 UDP 会话 / 包（对应 sing-tun `N.UDPConnectionHandlerEx.NewPacketConnectionEx`）。
    async fn new_packet(&self, packet: InboundUdpPacket);

    /// TUN 层 DNS 劫持查询（reflex-tun 的扩展点，sing-tun 无对应方法）。
    ///
    /// 返回 `true` 表示已消费该查询（会通过 `query.reply_tx` 异步回包）；
    /// 返回 `false` 表示不处理，协议栈会把对应的 UDP/TCP 流量当作普通流量
    /// 按 `new_packet` / `new_connection` 交付。默认实现返回 `false`。
    async fn new_dns_query(&self, _query: DnsQuery) -> bool {
        false
    }
}

/// 与 sing-tun `N.Network` 对齐的极简网络类型标记，供 [`Handler::prepare_connection`] 使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

// ── ChannelHandler ──────────────────────────────────────────────────────────

/// 反过来：把一组已有的 channel（本 crate 历史接口 [`crate::TunInbound::new`]
/// 用的那种）包装成一个 [`Handler`]。
///
/// 如果你的宿主项目已经有一套基于 `mpsc::Sender<InboundTcpStream>` /
/// `mpsc::Sender<InboundUdpPacket>` 的消费逻辑，想直接喂给 [`crate::new_stack`]
/// 而不改动消费端代码，用这个即可，不需要自己实现 [`Handler`]。
pub struct ChannelHandler {
    tcp_tx: tokio::sync::mpsc::Sender<InboundTcpStream>,
    udp_tx: tokio::sync::mpsc::Sender<InboundUdpPacket>,
    dns_tx: Option<DnsQueryTx>,
}

impl ChannelHandler {
    pub fn new(
        tcp_tx: tokio::sync::mpsc::Sender<InboundTcpStream>,
        udp_tx: tokio::sync::mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self {
            tcp_tx,
            udp_tx,
            dns_tx: None,
        }
    }

    /// 附加 DNS 劫持通道，等价于旧接口的 [`crate::TunInbound::with_dns_hijack`]。
    pub fn with_dns_hijack(mut self, dns_tx: DnsQueryTx) -> Self {
        self.dns_tx = Some(dns_tx);
        self
    }
}

/// 反方向适配器：把任意 [`Handler`] 暴露成 `TunInbound` 引擎所需要的三个
/// channel（tcp_tx / udp_tx / dns_tx），通过后台任务把 channel 收到的值转发
/// 给 `Handler` 的对应方法。引擎本身完全不感知调用方到底用的是 channel 还是
/// `Handler`。
///
/// 返回的三个 sender 的生命周期与传入的 `handler` 绑定：所有 sender 被 drop
/// 后，桥接任务会自然退出。
pub(crate) fn spawn_handler_bridge(
    handler: Arc<dyn Handler>,
    dns_hijack: bool,
) -> (
    tokio::sync::mpsc::Sender<InboundTcpStream>,
    tokio::sync::mpsc::Sender<InboundUdpPacket>,
    Option<DnsQueryTx>,
) {
    use tokio::sync::mpsc;

    let (tcp_tx, mut tcp_rx) = mpsc::channel::<InboundTcpStream>(1024);
    {
        let handler = handler.clone();
        tokio::spawn(async move {
            while let Some(conn) = tcp_rx.recv().await {
                handler.new_connection(conn).await;
            }
        });
    }

    let (udp_tx, mut udp_rx) = mpsc::channel::<InboundUdpPacket>(1024);
    {
        let handler = handler.clone();
        tokio::spawn(async move {
            while let Some(pkt) = udp_rx.recv().await {
                handler.new_packet(pkt).await;
            }
        });
    }

    let dns_tx = if dns_hijack {
        let (dns_tx, mut dns_rx) = mpsc::channel::<DnsQuery>(1024);
        tokio::spawn(async move {
            while let Some(query) = dns_rx.recv().await {
                if !handler.new_dns_query(query).await {
                    // Handler 选择不处理：查询直接被丢弃（reply_tx 被 drop，
                    // 调用方 await reply_rx 会收到错误，等价于查询超时/失败）。
                }
            }
        });
        Some(dns_tx)
    } else {
        None
    };

    (tcp_tx, udp_tx, dns_tx)
}

#[async_trait]
impl Handler for ChannelHandler {
    async fn new_connection(&self, conn: InboundTcpStream) {
        let _ = self.tcp_tx.send(conn).await;
    }

    async fn new_packet(&self, packet: InboundUdpPacket) {
        let _ = self.udp_tx.send(packet).await;
    }

    async fn new_dns_query(&self, query: DnsQuery) -> bool {
        match &self.dns_tx {
            Some(tx) => tx.send(query).await.is_ok(),
            None => false,
        }
    }
}
