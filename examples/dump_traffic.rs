//! 最小可运行示例：启动一个 TUN 设备，把所有经过它的 TCP 连接 / UDP 包
//! 打印到 stdout。
//!
//! 这个示例本身**不**做任何转发——它只演示 reflex-tun 与宿主项目之间的
//! 接口边界：你在 `tcp_rx` / `udp_rx` 两个 channel 上收到的东西，就是你
//! 需要接入自己路由 / 出站逻辑的地方。
//!
//! ## 运行方式
//!
//! 需要 root / 管理员权限（创建 TUN 设备的系统调用要求）：
//!
//! ```bash
//! sudo -E cargo run --example dump_traffic
//! ```
//!
//! 运行后，在另一个终端里访问网络（例如 `curl -4 ifconfig.me`），
//! 如果系统路由被正确接管（`auto_route: true`），流量会经过 TUN 被打印出来。
//!
//! Windows 下需要以管理员身份运行；示例内嵌了 wintun.dll，无需额外安装。

use reflex_tun::{InboundTcpStream, InboundUdpPacket, TunInbound, TunInboundConfig};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // 与 reflex 主项目 YAML/JSON 配置里 `type: tun` 的字段完全一致，
    // 可直接从配置文件反序列化。这里为了示例自包含，用字面量构造。
    let config: TunInboundConfig = serde_json::from_str(
        r#"{
            "tag": "tun-in",
            "interface_name": "reflex-tun-demo",
            "address": ["198.18.0.1/16"],
            "mtu": 9000,
            "auto_route": true,
            "strict_route": false,
            "stack": "system"
        }"#,
    )?;

    let (tcp_tx, mut tcp_rx) = mpsc::channel::<InboundTcpStream>(1024);
    let (udp_tx, mut udp_rx) = mpsc::channel::<InboundUdpPacket>(1024);

    // 消费入站 TCP 连接：真实项目中这里会转给路由层选择出站。
    let tcp_task = tokio::spawn(async move {
        while let Some(conn) = tcp_rx.recv().await {
            println!(
                "[tcp] tag={} target={} peer={:?}",
                conn.inbound_tag,
                conn.target,
                conn.stream.peer_addr()
            );
            // 示例直接丢弃连接（不转发）。真实项目应将 conn.stream 接入出站。
            drop(conn);
        }
    });

    // 消费入站 UDP 包：同上，真实项目会按 session 聚合后转发。
    let udp_task = tokio::spawn(async move {
        while let Some(pkt) = udp_rx.recv().await {
            println!(
                "[udp] tag={} target={} src={} len={}",
                pkt.inbound_tag,
                pkt.target,
                pkt.src,
                pkt.data.len()
            );
        }
    });

    println!("starting TUN inbound... (Ctrl+C to stop)");
    let run_result = TunInbound::new(config, tcp_tx, udp_tx).run().await;

    tcp_task.abort();
    udp_task.abort();
    run_result
}
