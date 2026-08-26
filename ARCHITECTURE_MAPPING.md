# rs-tun → sing-tun 风格改造说明

本次改造 **新增** 了一层 sing-tun 形状的公开 API，供其它 Rust 代理项目按
sing-tun 的心智模型使用；**未改动**原有的 channel 风格接口（`TunInbound::new` +
`mpsc`），两者背后共用同一套引擎，完全兼容并存。

## 改了什么 / 没改什么

| | 状态 |
|---|---|
| `src/handler.rs`（新增） | `Handler` trait + `ChannelHandler` 适配器 |
| `src/options.rs`（新增） | `Options` struct + 与 `TunInboundConfig` 互转 |
| `src/stack.rs`（新增） | `Tun` / `Stack` trait + `StackOptions` + `new_stack()` |
| `src/lib.rs` | 追加 `pub mod`/`pub use`，补充文档，**原有导出未删除** |
| `src/tun/mod.rs` | 仅新增 `TunInbound::with_handler()` 构造函数，**其余 3400+ 行未动** |
| `src/tun/gvisor.rs`、`native_tun.rs`、`platform/*`、NAT/校验和/分片等引擎逻辑 | **完全未动** |

## 概念映射（sing-tun Go → reflex-tun Rust）

| sing-tun (`tun.go` / `stack.go`) | reflex-tun |
|---|---|
| `type Handler interface { PrepareConnection / NewConnectionEx / NewPacketConnectionEx }` | `handler::Handler` trait（`prepare_connection` / `new_connection` / `new_packet`） |
| `type Options struct { Inet4Address, AutoRoute, MTU, ... }` | `options::Options`（字段名 snake_case 对应，如 `Inet4Address` → `inet4_address`） |
| `type Tun interface { Name/Start/Close/UpdateRouteOptions }` | `stack::Tun` trait（当前实现较薄，见下方“已知差异”） |
| `type Stack interface { Start/Close }` | `stack::Stack` trait |
| `StackOptions{ Tun, TunOptions, Handler }` | `stack::StackOptions{ tun_options, tag, handler, dns_hijack }` |
| `NewStack(stack string, options StackOptions)` | `stack::new_stack(options: StackOptions) -> Result<Box<dyn Stack>>`（`options.tun_options.stack` 决定 system/gvisor/mixed） |
| `stack.Start()` / `stack.Close()` | `Stack::start()` / `Stack::close()`（async） |

## 两种等价用法

```rust,ignore
// A. 历史 channel 接口（未改动）
TunInbound::new(config, tcp_tx, udp_tx).run().await?;

// B. 新增：sing-tun 风格
let mut stack = reflex_tun::new_stack(StackOptions {
    tun_options: options,       // Options { .. }
    tag: "tun-in".into(),
    handler: Arc::new(my_handler),
    dns_hijack: false,
}).await?;
stack.start().await?;
```

`ChannelHandler` 可以把已有的 `tcp_tx`/`udp_tx` 包装成 `Handler`，反之
`TunInbound::with_handler(config, handler, dns_hijack)` 把 `Handler` 桥接回
channel，两个方向都有，迁移成本很低。

## 已知差异（如实列出，供你判断是否需要进一步改造）

1. **`Tun`/`Stack` 未完全解耦**：sing-tun 里 `tun.New(options)` 和
   `tun.NewStack(...)` 是两个独立步骤，`Tun` 对象可以脱离 `Stack` 单独使用。
   现有引擎（`TunInbound::run()`）出于 GSO/GRO 卸载探测等平台细节，把「创建
   设备」和「协议栈处理循环」耦合在同一个函数里。这次改造为了不去动这段
   3400+ 行、未做编译验证的引擎代码，选择把这两步在 `new_stack()` 内部合并
   执行——`Stack::start()` 返回时设备已经在跑。如果你确实需要独立的
   `Tun::start()`/脱离协议栈单独读写裸包，需要在 `src/tun/mod.rs` 里把设备
   创建那一段（约 `run()` 函数中段，创建 `tun::Configuration` 到
   `NativeTun::with_gso().split()` 为止）进一步拆成独立函数——本次为控制风险
   没有做这一步。
2. **`Stack::close()` 非优雅关闭**：目前通过 `JoinHandle::abort()`
   中止后台任务，不会执行到 `auto_route` 的路由清理（引擎原来只有在读循环
   自然退出——即设备被关闭——时才会 `platform::teardown`）。生产环境如果
   依赖精确的路由清理，建议后续给引擎加一个 `CancellationToken`。
3. **`Options.gso` 字段是摆设**：引擎自动探测内核 TUNSETOFFLOAD 能力，不读
   这个字段；保留它只是为了跟 sing-tun 字段形状对齐。
4. **`Tun::name()` 恒返回 `None`**：接口名目前只进了 tracing 日志，没有回传
   到 `Stack`/`Tun` 对象。想要拿到真实接口名，需要给引擎加一个
   `oneshot::Sender<String>` 在设备创建后立即回传。

## 关于编译验证

本次沙盒环境的 rustc 版本（Ubuntu 24.04 自带的 1.75）低于 `tun`/`smoltcp`
等依赖要求的 edition2024，且沙盒网络无法访问 rustup 官方发布渠道升级工具链，
**因此这次改造没有做 `cargo check`/`cargo build` 验证**，只做了人工逐行核对
+ 括号配平检查。建议你在自己的机器上跑一遍：

```bash
cargo check
cargo doc --no-deps --open   # 顺便看看 rustdoc 渲染效果
```

如果发现类型不匹配等问题，大概率集中在 `src/options.rs` 的
`to_options`/`to_config` 互转部分（字段最多、最容易犯低级错误），其余两个
新文件（`handler.rs`、`stack.rs`）逻辑更简单。
