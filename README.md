# reflex-tun

跨平台 TUN 虚拟网卡入站实现，从 [reflex](https://github.com/) 代理项目中拆分而来，
供任意 Rust 编写的代理 / 网络工具复用。

支持 **Linux / macOS / Windows / Android**，内置两种网络栈：

- **`system`**：依赖内核网络栈做 L3→L4 转换，性能最佳（Linux / macOS / Windows）
- **`gvisor`**：基于 [smoltcp](https://github.com/smoltcp-rs/smoltcp) 的用户态协议栈，兼容性更强，各平台通用
- **`mixed`**：TCP 走 system，UDP 走 gvisor（折中方案）

## 这个 crate 做什么，不做什么

**做**：创建/配置 TUN 设备、（可选）自动配置系统路由（`auto_route`）、
L3 → L4 拆包（IP 包 → TCP 连接 / UDP 包），并把结果通过 `tokio::mpsc`
channel 交出来。

**不做**：DNS 解析、按规则路由、出站协议实现。这些完全由你的项目决定——
拿到 `InboundTcpStream` / `InboundUdpPacket` 后接入你自己的转发管线即可。

这个边界是从 reflex 主项目里原样保留的：`TunInbound` 在 reflex 内部就是
通过这几个 channel 与 dispatcher / router 通信，拆分时没有改动这层接口。

## 快速上手

```toml
[dependencies]
reflex-tun = { git = "https://github.com/your-org/reflex-tun" }
# 或者先在本地验证：
# reflex-tun = { path = "../reflex-tun" }
tokio = { version = "1", features = ["full"] }
```

```rust,ignore
use reflex_tun::{TunInbound, TunInboundConfig};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: TunInboundConfig = serde_json::from_str(r#"{
        "tag": "tun-in",
        "address": ["198.18.0.1/16"],
        "auto_route": true,
        "stack": "system"
    }"#)?;

    let (tcp_tx, mut tcp_rx) = mpsc::channel(1024);
    let (udp_tx, mut udp_rx) = mpsc::channel(1024);

    tokio::spawn(async move {
        while let Some(conn) = tcp_rx.recv().await {
            // conn.stream: 实现 AsyncRead + AsyncWrite 的 TCP 流
            // conn.target: 连接目标（Target::Domain 或 Target::Socket）
            // 接入你自己的路由 / 出站逻辑
        }
    });
    tokio::spawn(async move {
        while let Some(pkt) = udp_rx.recv().await {
            // pkt.data / pkt.src / pkt.target / pkt.session（用于回包）
        }
    });

    TunInbound::new(config, tcp_tx, udp_tx).run().await
}
```

完整可运行示例见 [`examples/dump_traffic.rs`](examples/dump_traffic.rs)：

```bash
sudo -E cargo run --example dump_traffic
```

## sing-tun 风格用法

如果你更熟悉 [sing-tun](https://github.com/SagerNet/sing-tun)（sing-box 底层用的 TUN 库）的
`Options` / `Handler` / `Stack` 心智模型，本 crate 提供了一套形状对应的接口，
背后是同一套引擎，两种用法可以任选：

```rust,ignore
use std::sync::Arc;
use async_trait::async_trait;
use reflex_tun::{Handler, InboundTcpStream, InboundUdpPacket, Options, StackKind, StackOptions};

struct MyHandler;

#[async_trait]
impl Handler for MyHandler {
    async fn new_connection(&self, conn: InboundTcpStream) {
        // 对应 sing-tun Handler.NewConnectionEx：拿到 TCP 连接后自行路由/转发
        let _ = conn;
    }
    async fn new_packet(&self, packet: InboundUdpPacket) {
        // 对应 sing-tun Handler.NewPacketConnectionEx
        let _ = packet;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Options {
        inet4_address: vec![("198.18.0.1".parse().unwrap(), 16)],
        auto_route: true,
        stack: StackKind::System, // 或 Gvisor / Mixed
        ..Options::default()
    };

    let mut stack = reflex_tun::new_stack(StackOptions {
        tun_options: options,
        tag: "tun-in".to_string(),
        handler: Arc::new(MyHandler),
        dns_hijack: false,
    })
    .await?;

    stack.start().await?;
    // stack.close().await?; // 需要主动停止时调用
    std::future::pending::<()>().await;
    Ok(())
}
```

字段命名对照（Go → Rust）：`Options.Inet4Address` → `Options::inet4_address`，
`Options.AutoRoute` → `auto_route`，`NewStack(stack, ...)` → `new_stack(StackOptions { tun_options: Options { stack, .. }, .. })`。
详见 [`src/stack.rs`](src/stack.rs) 顶部文档注释，里面如实列出了与 sing-tun 的几点行为差异
（主要是 `Tun` 创建与 `Stack` 启动在本 crate 里是合并成一步的，`close()` 目前通过中止
后台任务实现，不保证执行路由清理）。

## 配置字段

`TunInboundConfig` 与 reflex 主项目 YAML/JSON 配置中 `type: tun` 的入站
定义逐字段对应，可直接复用同一份配置片段。字段文档见
[`src/config.rs`](src/config.rs) 内联注释，涵盖：

- 地址 / MTU / 设备名
- `auto_route` 自动路由（Linux 用独立路由表 + 策略路由；macOS 用 `AF_ROUTE`；
  Windows 用 `CreateIpForwardEntry2`）
- `strict_route` 严格路由模式
- Linux 专用：`iproute2_table_index` / `iproute2_rule_index` / `so_mark` /
  interface & UID 白名单黑名单 / `auto_redirect`（nftables TPROXY）
- Android 专用：`include_android_user` / `include_package` / `exclude_package`
- 跨平台：`route_address` / `route_exclude_address` / `loopback_address` /
  `tcp_mss`

## 从 reflex 主项目迁移

如果你正在维护 reflex 本身，把内嵌的 `src/inbound/tun` 换成依赖本 crate：

1. `Cargo.toml` 加入 `reflex-tun = { path = "../reflex-tun" }`（或 git 依赖）
2. 删除 `src/inbound/tun/` 整个目录
3. `src/inbound/mod.rs` 中把 `pub mod tun;` 换成：
   ```rust,ignore
   pub use reflex_tun::{TunInbound, DnsQuery, DnsQuerySource, DnsQueryTx};
   ```
4. `src/config/inbound.rs` 中把 `TunInboundConfig` 定义换成
   `pub use reflex_tun::TunInboundConfig;`（或做一层 newtype 转换，
   如果你希望保留对该类型的本地扩展能力）
5. 其余引用 `crate::inbound::tun::TunInbound` /
   `crate::config::inbound::TunInboundConfig` 的地方改为
   `reflex_tun::TunInbound` / `reflex_tun::TunInboundConfig`

`InboundTcpStream` / `InboundUdpPacket` / `Target` / `UdpSession` /
`SniffedStream` 这几个类型在本 crate 与 reflex 主项目 `src/inbound/mod.rs`
中定义完全一致（字段一一对应），如果 reflex 主项目也想统一用本 crate 的
定义，可以把本地定义替换为 `pub use reflex_tun::{...}`，减少一份重复代码。

## 支持矩阵

| 平台 | system 栈 | gvisor 栈 | auto_route | strict_route |
|------|:---:|:---:|:---:|:---:|
| Linux | ✅ | ✅ | ✅（iproute2 独立表 + 策略路由，可选 nftables TPROXY auto_redirect） | ✅（缺失地址族的 unreachable 规则） |
| macOS | ✅ | ✅ | ✅（`AF_ROUTE` socket） | — （macOS 无对应内核机制） |
| Windows | ✅ | ✅ | ✅（`CreateIpForwardEntry2`，内嵌 wintun.dll） | ✅（WFP，需 Windows 10+） |
| Android | ✅ | ✅ | 由宿主 App 通过 `VpnService` 建立后传入 fd | — |

> **已知限制**：仓库内嵌的 wintun.dll 目前只包含 `amd64` 与 `x86` 两个架构
> （见 [`src/tun/assets/wintun/`](src/tun/assets/wintun/)）。若需要
> `aarch64-pc-windows-msvc` 上的运行时支持，需要自行补充
> `wintun-arm64.dll` 并调整 `src/tun/platform/windows.rs` 中的
> `include_bytes!` 路径 —— 这是从 reflex 主项目原样继承的缺口，不是拆分
> 过程中引入的新问题。CI 中的 `aarch64-pc-windows-msvc` job 目前只做
> `cargo check`（类型检查），不做实际链接/运行验证。

## 开发

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo run --example dump_traffic   # 需要 root / 管理员权限
```

CI（见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)）覆盖：

- **原生构建 + 测试 + clippy + doctest**：`x86_64-unknown-linux-gnu`、
  `aarch64-apple-darwin`、`x86_64-pc-windows-msvc`
- **交叉 `cargo check`**：`aarch64-unknown-linux-{gnu,musl}`、
  `aarch64-linux-android`、`armv7-linux-androideabi`、
  `x86_64-linux-android`（通过 `cargo-ndk`）、`aarch64-pc-windows-msvc`
- **下游集成 smoke test**：在三大平台上各自新建一个最小的 consumer
  crate，通过 `path` 依赖引用本 crate 并完成一次真实的类型构造 + 编译，
  验证「其它 Rust 项目引用本 crate」这条路径本身是通的

## 许可证

拆分自 reflex 主项目；原仓库未附带独立的 `LICENSE` 文件，实际许可证条款
请以 reflex 主项目仓库为准，在明确授权前不建议直接对外分发本 crate。
内嵌的 `wintun.dll` 遵循 WireGuard LLC 的 Prebuilt Binaries License
（见 [wintun.net](https://www.wintun.net/)），不随 crate 的 Rust 代码
许可证变化。
