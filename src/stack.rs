//! sing-tun 风格的 `Tun` / `Stack` 接口，是本 crate 面向其它 Rust 代理项目的
//! 主要入口，等价于 sing-tun 的：
//!
//! ```go
//! t, err := tun.New(options)
//! stack, err := tun.NewStack(stackType, tun.StackOptions{
//!     Tun:        t,
//!     TunOptions: options,
//!     Handler:    handler,
//! })
//! err = stack.Start()
//! ```
//!
//! ## 与 sing-tun 的差异（如实说明，避免误用）
//!
//! sing-tun 把「创建/打开 TUN 设备」（`tun.New`）和「启动协议栈处理循环」
//! （`stack.Start`）拆成两个独立步骤，`Tun` 对象在两者之间可以单独使用
//! （比如只用来读写裸包，不经过协议栈）。
//!
//! 本 crate 现有引擎（[`crate::tun::TunInbound`]）出于 GSO/GRO 卸载探测等
//! 平台细节，把「创建设备」和「协议栈处理循环」耦合在同一个 `async fn run()`
//! 里，一次性完成。为了不去动这段已经过大量平台细节打磨、且本次改造未做
//! 编译验证的引擎代码，这里的 [`new_stack`] 把 sing-tun 的两步合并成一步：
//! 调用后台任务里既创建设备、也立即开始处理循环，`Stack::start()` 返回时
//! 设备已经在跑。[`Tun`] trait 仍然按 sing-tun 的形状提供，供你在自己的
//! `Handler` 实现里需要时使用；如果你需要真正独立的「只开设备不跑协议栈」
//! 步骤，可以在此基础上把 `tun/mod.rs` 里创建设备的那段进一步拆出来。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::task::JoinHandle;

use crate::handler::Handler;
use crate::options::Options;

/// 对应 sing-tun `tun.Tun`：底层 TUN 设备的最小可观察接口。
///
/// `new_stack` 返回的 [`Stack`] 内部持有一个满足此 trait 的设备句柄
/// （见 [`Stack::tun`]）；如果你想在本 crate 的引擎之外自己实现设备管理
/// （例如把已经打开的 fd 传进来），也可以自行实现这个 trait。
pub trait Tun: Send + Sync {
    /// 接口名（Linux `tun0`、macOS `utun3`、Windows 由 wintun 分配等）。
    ///
    /// 当前实现恒为 `None`：引擎在设备创建成功后只把接口名写进 tracing 日志
    /// （`tun inbound started` 一条，字段 `interface`），未回传到 `Stack` 层。
    /// 如果你需要以编程方式拿到接口名，可以在此基础上给引擎加一个
    /// `oneshot::Sender<String>` 在设备创建后立即回传，这里预留了接口形状。
    fn name(&self) -> Option<String>;
}

/// 占位 Tun 句柄：`new_stack` 内部使用。
pub(crate) struct TunHandle;

impl Tun for TunHandle {
    fn name(&self) -> Option<String> {
        None
    }
}

/// 对应 sing-tun `tun.Stack`。
#[async_trait]
pub trait Stack: Send + Sync {
    /// 启动协议栈处理循环。对应 sing-tun `Stack.Start()`。
    ///
    /// 与 sing-tun 同步阻塞语义不同，这里在内部把处理循环放进一个后台任务，
    /// `start()` 本身立即返回；引擎运行期间产生的所有连接/数据包都会通过
    /// [`StackOptions::handler`] 回调出来。
    async fn start(&mut self) -> anyhow::Result<()>;

    /// 关闭协议栈（对应 sing-tun `Stack.Close()`）。
    ///
    /// 当前实现通过中止后台任务完成，**不保证**执行到 `auto_route` 的路由
    /// 清理逻辑（引擎原本只在读循环自然退出——即设备被关闭——时才会 teardown）。
    /// 如果你的场景依赖精确的路由清理，请自行在进程退出前调用平台工具
    /// （`ip route` / `route` / 等）兜底，或者在此基础上给引擎加一个
    /// `CancellationToken` 做优雅退出。
    async fn close(&mut self) -> anyhow::Result<()>;

    /// 关联的 [`Tun`] 设备句柄。
    fn tun(&self) -> &dyn Tun;
}

/// 对应 sing-tun `tun.StackOptions`。
pub struct StackOptions {
    /// 运行期选项（对应 `StackOptions.TunOptions`）。
    pub tun_options: Options,
    /// 入站标识（本 crate 引擎要求，sing-tun 无此字段，日志 / 路由匹配用）。
    pub tag: String,
    /// 连接回调（对应 `StackOptions.Handler`）。
    pub handler: Arc<dyn Handler>,
    /// 是否启用 TUN 层 DNS 劫持（reflex-tun 扩展点，见 [`crate::handler::Handler::new_dns_query`]）。
    pub dns_hijack: bool,
}

struct EngineStack {
    tun: Arc<TunHandle>,
    task: Option<JoinHandle<()>>,
}

#[async_trait]
impl Stack for EngineStack {
    async fn start(&mut self) -> anyhow::Result<()> {
        // 引擎（TunInbound::run）已经在 new_stack() 里被 spawn，这里只是把
        // “start 已完成”的语义补齐；真正出错的情况通过 tracing::error! 日志
        // 观察（run() 的 Result 在后台任务里被丢弃前已打点日志）。
        if self.task.is_none() {
            anyhow::bail!("stack already closed");
        }
        Ok(())
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        Ok(())
    }

    fn tun(&self) -> &dyn Tun {
        self.tun.as_ref()
    }
}

/// 对应 sing-tun `tun.NewStack(stack string, options StackOptions)`。
///
/// `options.tun_options.stack` 决定使用哪种协议栈（system / gvisor / mixed），
/// 与 sing-tun `NewStack` 按字符串分发的语义一致。
pub async fn new_stack(options: StackOptions) -> anyhow::Result<Box<dyn Stack>> {
    let StackOptions {
        tun_options,
        tag,
        handler,
        dns_hijack,
    } = options;

    let config = tun_options.to_config(tag);
    let tun_handle = Arc::new(TunHandle);

    let inbound = crate::tun::TunInbound::with_handler(config, handler, dns_hijack);
    let task = tokio::spawn(async move {
        if let Err(e) = inbound.run().await {
            tracing::error!(err = %e, "reflex-tun: stack exited with error");
        }
    });

    Ok(Box::new(EngineStack {
        tun: tun_handle,
        task: Some(task),
    }))
}
