//! # reflex-tun
//!
//! 独立的 TUN 虚拟网卡入站实现，从 [reflex](https://github.com/) 项目中拆分而来，
//! 供任意 Rust 编写的代理 / 网络工具复用。
//!
//! 支持 Linux / macOS / Windows / Android，提供两种网络栈：
//! - `system`：依赖内核网络栈做 L3→L4 转换，性能最佳（Linux/macOS/Windows）
//! - `gvisor`：用户态 gVisor 风格协议栈（基于 smoltcp），兼容性更强，各平台通用
//!
//! ## 快速上手
//!
//! ```ignore
//! use reflex_tun::{TunInbound, TunInboundConfig};
//! use tokio::sync::mpsc;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config: TunInboundConfig = serde_json::from_str(r#"{
//!     "tag": "tun-in",
//!     "address": ["198.18.0.1/16"],
//!     "auto_route": true,
//!     "stack": "system"
//! }"#)?;
//!
//! let (tcp_tx, mut tcp_rx) = mpsc::channel(1024);
//! let (udp_tx, mut udp_rx) = mpsc::channel(1024);
//!
//! // 消费入站连接：交给你自己的路由 / 出站转发逻辑
//! tokio::spawn(async move {
//!     while let Some(conn) = tcp_rx.recv().await {
//!         // conn.stream / conn.target / conn.inbound_tag ...
//!         let _ = conn;
//!     }
//! });
//! tokio::spawn(async move {
//!     while let Some(pkt) = udp_rx.recv().await {
//!         let _ = pkt;
//!     }
//! });
//!
//! TunInbound::new(config, tcp_tx, udp_tx).run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 接口边界
//!
//! 本 crate 只负责：创建/配置 TUN 设备、（可选）自动配置系统路由、L3→L4 拆包，
//! 并把还原出的 TCP 连接 / UDP 包交出去。
//!
//! 它**不**负责：DNS 解析、按规则路由、出站协议实现——这些完全由宿主项目决定。
//!
//! ## 两套等价的对外接口
//!
//! - **channel 风格**（历史接口，见上面的例子）：[`TunInbound::new`] + `mpsc`。
//! - **sing-tun 风格**（推荐给熟悉 [sing-tun](https://github.com/SagerNet/sing-tun)
//!   的调用方）：[`Options`] + [`Handler`] + [`new_stack`]，形状对应 sing-tun 的
//!   `tun.Options` / `tun.Handler` / `tun.NewStack`。两者背后是同一套引擎，
//!   `Handler` 与 channel 之间可以用 [`ChannelHandler`] 互转，选哪种纯粹是
//!   调用方习惯问题。见 [`stack`] 模块文档了解与 sing-tun 的具体差异。

pub mod config;
pub mod handler;
pub mod interface_finder;
pub mod options;
pub mod stack;
mod tun;
pub mod types;

pub use config::TunInboundConfig;
pub use handler::{ChannelHandler, Handler, Network};
pub use options::{Options, Prefix, StackKind, UidRange};
pub use stack::{new_stack, Stack, StackOptions, Tun};
pub use tun::TunInbound;
pub use types::{
    DnsQuery, DnsQuerySource, DnsQueryTx, InboundTcpStream, InboundUdpPacket, SniffedStream,
    Target, UdpSession,
};

// ── sing-tun 风格用法示例 ─────────────────────────────────────────────────────
//
// ```ignore
// use std::sync::Arc;
// use async_trait::async_trait;
// use reflex_tun::{Handler, InboundTcpStream, InboundUdpPacket, Options, StackKind, StackOptions};
//
// struct MyHandler;
//
// #[async_trait]
// impl Handler for MyHandler {
//     async fn new_connection(&self, conn: InboundTcpStream) {
//         // 交给自己的路由 / 出站逻辑
//         let _ = conn;
//     }
//     async fn new_packet(&self, packet: InboundUdpPacket) {
//         let _ = packet;
//     }
// }
//
// # async fn example() -> anyhow::Result<()> {
// let options = Options {
//     inet4_address: vec![("198.18.0.1".parse().unwrap(), 16)],
//     auto_route: true,
//     stack: StackKind::System,
//     ..Options::default()
// };
//
// let mut stack = reflex_tun::new_stack(StackOptions {
//     tun_options: options,
//     tag: "tun-in".to_string(),
//     handler: Arc::new(MyHandler),
//     dns_hijack: false,
// })
// .await?;
// stack.start().await?;
// # Ok(())
// # }
// ```
