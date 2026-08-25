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
//! 并把还原出的 TCP 连接 / UDP 包通过 mpsc channel 交出去。
//!
//! 它**不**负责：DNS 解析、按规则路由、出站协议实现——这些完全由宿主项目决定，
//! 通过消费 [`InboundTcpStream`] / [`InboundUdpPacket`] 来接入自己的转发管线。

pub mod config;
pub mod interface_finder;
mod tun;
pub mod types;

pub use config::TunInboundConfig;
pub use tun::TunInbound;
pub use types::{
    DnsQuery, DnsQuerySource, DnsQueryTx, InboundTcpStream, InboundUdpPacket, SniffedStream,
    Target, UdpSession,
};
