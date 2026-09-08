<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="A3S Gateway 在本地 Rust 数据平面中度量并治理 AI token 流量">
</p>

<p align="center">
  <strong>Language / 语言:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>

<p align="center">
  <strong>在一个本地 Rust 数据平面中，提供 OpenAI 兼容的模型策略、token 流生命周期、后端恢复与原子期望状态。</strong>
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/Gateway/actions/workflows/ci.yml"><img alt="CI 状态" src="https://img.shields.io/github/actions/workflow/status/A3S-Lab/Gateway/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/A3S-Lab/Gateway/releases/latest"><img alt="最新 A3S Gateway 发布" src="https://img.shields.io/github/v/release/A3S-Lab/Gateway?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=1264ff"></a>
  <a href="https://crates.io/crates/a3s-gateway"><img alt="crates.io 上的 a3s-gateway" src="https://img.shields.io/crates/v/a3s-gateway?style=flat-square&amp;color=0c8a65"></a>
  <a href="https://www.rust-lang.org/"><img alt="最低支持的 Rust 版本 1.88" src="https://img.shields.io/badge/MSRV-1.88-56657b?style=flat-square"></a>
  <a href="LICENSE"><img alt="MIT 许可证" src="https://img.shields.io/badge/license-MIT-101827?style=flat-square"></a>
</p>

<p align="center">
  <a href="https://a3s-lab.github.io/Gateway/">网站</a> &middot;
  <a href="https://a3s-lab.github.io/Gateway/docs/">文档</a> &middot;
  <a href="#快速开始">快速开始</a> &middot;
  <a href="#ai-流量证据">AI 证据</a> &middot;
  <a href="ROADMAP.md">路线图</a>
</p>

---

A3S Gateway 位于 OpenAI 兼容客户端与模型后端之间。它认证并准入请求，解析模型别名，选择健康目标，并在无需同步控制平面往返的情况下保持流式响应。同一二进制还路由 HTTP/1.1、HTTP/2、SSE、WebSocket、gRPC、TCP、UDP 与 TLS 流量。

在 `standalone` 模式下使用本地 ACL，或在 `cloud-managed` 模式下应用来自 A3S Cloud 的完整、带修订绑定的期望状态。Gateway 拥有实时流量决策；Cloud 拥有人工运维、发布、放置与长期用量账本。

## AI 流量证据

<p align="center">
  <img src="assets/readme/ai-evidence.svg" width="100%" alt="A3S Gateway 与 NGINX 的 token 感知基准序列与公平性契约">
</p>

已发布的核心对比在同一主机上使用一个确定性的 OpenAI 兼容上游。它对八个配置中的每一个交替运行 A3S Gateway 与 NGINX 五次，并拒绝任何 token 缺失、乱序或终端标记不是恰好一个的试验。共 80 次原始产品试验全部成功，并记录了 TTFT、ITL、TPOT、端到端延迟、流速率与完成 token 有效吞吐。

| 工作负载 | A3S TTFT | NGINX TTFT | TTFT 比率 | ITL 比率 | Token 有效吞吐比率 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 零延迟流 · C1 | 0.343 ms | 0.349 ms | 0.983× | 0.992× | 1.000× |
| 零延迟流 · C64 | 2.438 ms | 1.184 ms | 2.059× | 0.986× | 0.924× |
| 节拍流 · C16 | 51.421 ms | 51.427 ms | 1.000× | 1.000× | 1.001× |
| 节拍流 · C64 | 52.274 ms | 52.152 ms | 1.002× | 0.995× | 1.001× |
| 长输出 | 51.877 ms | 51.848 ms | 1.001× | 1.002× | 1.000× |
| Completions 端点 | 51.450 ms | 51.811 ms | 0.993× | 0.985× | 1.001× |
| 32 KiB 提示 | 51.633 ms | 51.860 ms | 0.996× | 1.013× | 1.001× |
| 256 KiB 提示 | 52.928 ms | 52.660 ms | 1.005× | 0.994× | 0.998× |

比率大于 1 表示 A3S 更慢，或（取决于列）NGINX 产出更多有效吞吐。零延迟 C64 行暴露了当前真实瓶颈；节拍、长输出、端点与长提示行在此托管 runner 上接近持平。A3S 执行有界的 OpenAI JSON 与模型校验；NGINX 是仅传输对照，因此这衡量的是开启功能路径的代价，而非等价策略能力，也非生产容量。

[原始 token 感知 JSON](https://a3s-lab.github.io/Gateway/assets/ai-gateway-comparison.json) ·
[确切工作流运行](https://github.com/A3S-Lab/Gateway/actions/runs/31671953391) ·
[59 场景方法与待办](benchmarks/ai-gateway-comparison/README.md)

## 快速开始

在 macOS 或 Linux 上安装：

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://a3s-lab.github.io/Gateway/install.sh | sh
```

在 Windows PowerShell 上安装：

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; irm https://a3s-lab.github.io/Gateway/install.ps1 | iex
```

也支持 Cargo 与 Homebrew：

```bash
cargo install a3s-gateway
# or
brew install a3s-lab/tap/a3s-gateway
```

在 `127.0.0.1:8000` 有 OpenAI 兼容后端时，将其保存为 `gateway.acl`：

```acl
mode { kind = "standalone" }

entrypoints "web" {
  address = "127.0.0.1:8080"
}

routers "models" {
  rule        = "PathPrefix(`/v1`)"
  service     = "models"
  entrypoints = ["web"]
}

services "models" {
  load_balancer {
    strategy             = "least-connections"
    request_timeout      = "30s"
    stream_idle_timeout  = "5m"
    stream_total_timeout = "60m"
    servers = [{ url = "http://127.0.0.1:8000" }]
  }
}
```

启动前校验完整快照：

```bash
a3s-gateway validate --config gateway.acl
a3s-gateway config --config gateway.acl summary
a3s-gateway --config gateway.acl
curl http://127.0.0.1:8080/v1/models
```

## 为何需要 AI 流量层

| AI 流量需求 | Gateway 机制 |
| --- | --- |
| 首 token 与长流失败模式 | 分离首响应、空闲流与总操作边界，配合背压与有界排空 |
| 按模型访问控制 | 端点/模型授权、别名改写、RPM、突发、并发请求准入，以及本地 `tokens_per_minute` 预约 |
| 不均衡或故障的提供方 | 主动/被动健康、熔断状态、加权选择、故障转移，且仅在响应开始前重试 |
| 安全的策略变更 | 校验并编译完整快照，再原子激活；拒绝时保留先前运行时 |
| 远程期望状态 | 应用完整 Cloud 快照，同时每个已授权请求决策仍保持本地 |
| 缩容到零的工作负载 | 消费 A3S Box 的就绪副本端点，仅在工作负载可路由后放行有界请求 |

这刻意窄于 AI 平台。Gateway 不拥有租户、部署、放置、发布、计费、模型服务或人工操作员 UI。

## 架构

<p align="center">
  <img src="assets/readme/architecture.svg" width="100%" alt="独立 ACL 或 A3S Cloud 期望状态激活一个本地 Gateway 快照，路由到健康的模型后端">
</p>

| 模式 | 期望状态所有者 | Gateway 职责 |
| --- | --- | --- |
| `standalone` | 本地操作员与 ACL | 校验并执行路由、中间件、提供方、健康、静态修订权重与可选扩缩 |
| `cloud-managed` | A3S Cloud | 校验并执行一个完整的身份、修订、摘要、CAS 与过期绑定快照 |

更改权威需要进程重启。Gateway 暴露仅供机器使用的 Node API，用于健康、就绪、指标、版本、托管快照应用、确切快照状态与本地用量假脱机状态。

### Gateway 与 A3S Box

Gateway 与 [A3S Box](https://github.com/A3S-Lab/a3s-box) 解决同一请求生命周期的不同部分。Gateway 拥有准入、路由、健康与流保真。Box 拥有 Sandbox 工作负载状态，并发布就绪的副本槽端点。在 standalone 模式下，可选的 Box 执行器可从零扩容、原子替换实时后端池、放行有界等待请求，并在 Box 排空并终止其工作负载前撤回端点。

该集成已有本地、真实 Gateway、真实 Kubernetes 与确切修订的真实 Linux Box Sandbox 证据。真实 MicroVM 工作负载门仍开放，因此 standalone 自动扩缩仍属实验性。`cloud-managed` 流量不会调用 Box；在那里 Cloud 仍是期望副本权威。

## 能力状态

| 领域 | 状态 | 当前边界 |
| --- | --- | --- |
| 协议与流平面 | 可用 | HTTP/1.1、HTTP/2、SSE、WebSocket、原生 gRPC over h2c、TCP、UDP、TLS、trailer、背压、独立流边界与有界排空 |
| 路由、中间件、健康 | 可用 | HTTP 族入口的 Host/path/method/header 规则；TCP 入口在 ClientHello peek 后匹配纯 `HostSNI(...)` 规则（无 HostSNI 路由时，非 TLS TCP 仍使用遗留 path/method 匹配）。内置策略、类型化 Rust 扩展、四种均衡策略、健康、熔断、粘性会话、故障转移与镜像 |
| DNS 服务发现 | ACL 中不可用 | `src/provider/dns.rs` 仍是未接线的辅助；ACL `providers` 仅接受 `file`、`discovery`、`kubernetes` 与 `docker` |
| 传统 WAF | 不可用 | 不在产品范围内。可选 Cargo feature `wire` 通过 `a3s-sentry` 提供 agentfw 风格的 LLM/MCP 正文防火墙（在 `/wire/<agent>/...` 上做密钥/PII 掩码与注入阻断）；它不是 OWASP/ModSecurity WAF，也不属于默认数据平面 |
| 快照生命周期 | 可用 | Standalone ACL 与 Cloud 托管模式、失败即关闭校验、监听器对账、原子激活、确切就绪与可选托管状态恢复 |
| 托管目标投递（`H0.2`） | 联合验证 | 已发布 Gateway 加上固定的 Cloud 干净主机门覆盖确切 apply/ACK、进程丢失、重投递、冲突/过期拒绝、证书与目标代际替换、副本本地就绪与协议兼容 |
| 托管 Runtime Service 路由 | Gateway 基础 | 嵌入式主机可持久绑定一个确切的 loopback Runtime 代际，通过真实 Gateway 路由验证健康，隐藏准入，排空已接受流，仅移除收据拥有的状态，并在重启后恢复不透明绑定身份。A3S Use/Code 组合与发布资格仍开放。 |
| 托管 OpenAI 路径 | Gateway 基础 | Models、chat completions、completions、embeddings、授权、改写、准入、请求/尝试身份、健康感知目标与响应前回退 |
| 分布式推理路由 | Gateway/Power 数据平面 | 聚合调度加上独立的 prefill/decode 对选择、经认证的配置文件绑定 Power 编排、不透明状态句柄中继、OpenAI JSON/SSE 翻译、有界清理、对回退与 Gateway 本地滚动版本符合性；Cloud 发布与跨产品资格仍开放 |
| 用量投递 | Gateway 基础 | 无提示的有界假脱机、完整性、重启恢复、有序重放、连续确认、回收、压缩、冻结的 Cloud batch/ACK 契约、HTTP Bearer 传输，以及可选的 bootstrap 上传配对（`docs/usage-cloud-ingest.md`）；Cloud 账本摄取与联合崩溃/重放证据仍开放 |
| Standalone 自动扩缩 | 实验性 | 已有 Box 与 Kubernetes 恢复证据；真实 MicroVM 工作负载符合性仍开放 |
| 自动渐进发布 | 不可用 | `rollout {}` 被拒绝；托管发布是 Cloud 决策 |
| 面向文本模型的多模态适配 | 仅设计 | 原生多模态上游内容原样透传。VLM/OCR/ASR 到文本的适配已提出，但未在 v1.1.0 中交付 |

请阅读确切的 [E0/H0.2 符合性记录](docs/cloud-managed-e0-conformance.md)、
[分布式推理路由契约](docs/distributed-inference-routing.md)
以及[完整成熟度路线图](ROADMAP.md)。「可用」表示已交付；「联合验证」指名跨仓库证据；「基础」仍有跨产品工作；「实验性」仍为可选启用。

## 多模态输入与纯文本模型

Gateway 已可保留上游原生支持的 OpenAI 多模态内容。若要让纯文本目标消费同一请求，则需要显式、有损的预处理层：

```text
image / audio / video -> bounded VLM / OCR / ASR -> provenance-bearing text -> text LLM
```

这可使文本模型成为**多模态辅助**；它不能使模型本身内在多模态。从 Qwen-MM-Plugins 学到的设计、正确的原生推理插入点、SSRF 与提示注入控制、真实 TTFT 核算、失败语义与广泛评估矩阵，记录在[多模态适配提案](docs/multimodal-adaptation.md)中。v1.1.0 未启用任何适配器。

## AI 流量之外的性能

可复现的同主机套件还在 HTTP/1.1、HTTPS、HTTP/2、gRPC、SSE、WebSocket、TCP、UDP、OpenAI JSON 与 OpenAI 流上交替运行 A3S Gateway 与 NGINX。它为每次原始试验发布吞吐以及平均、P50、P90、P99 延迟。这些配置检测协议回归；上方的 token 感知通道是主要的模型流量证据。

[已发布矩阵](https://a3s-lab.github.io/Gateway/#performance) ·
[协议对比 JSON](website/assets/performance-comparison.json) ·
[Criterion JSON](website/assets/performance-data.json) ·
[方法说明](benchmarks/README.md)

## 部署或嵌入

Docker：

```bash
docker run --rm \
  -v "$PWD/gateway.acl:/etc/gateway/gateway.acl:ro" \
  -p 8080:8080 \
  ghcr.io/a3s-lab/gateway:latest \
  --config /etc/gateway/gateway.acl
```

Helm：

```bash
helm install gateway deploy/helm/a3s-gateway \
  --set image.repository=ghcr.io/a3s-lab/gateway \
  --set-file config=./gateway.acl
```

Rust 库：

```bash
cargo add a3s-gateway
```

可选 Cargo feature：

| Feature | 增加内容 |
| --- | --- |
| `redis` | 基于 Redis 的分布式限流 |
| `kube` | Kubernetes Ingress 提供方与 Scale 执行器 |
| `wire` | 通过 `a3s-sentry` 做内联 LLM/MCP 密钥与 PII 检查 |

嵌入式 Rust 部署还可通过 `MiddlewareRegistry` 注册类型化请求/响应中间件；独立二进制不加载动态库或 Wasm 插件。参见[中间件指南](https://a3s-lab.github.io/Gateway/docs/#middleware)。

嵌入式 A3S 主机还可使用绝对私有的 Managed Service 状态文件构造 Gateway。程序化生命周期仅将 loopback Runtime 上游绑定到明文 loopback HTTP 入口，将操作员或 Cloud ACL 保留为基础期望状态，并在更改实时路由前持久化覆盖层。确切的绑定、健康、排空、移除、重放与恢复契约见 [Managed Runtime Service 生命周期](docs/managed-runtime-services.md)。

## 开发

需要 Rust 1.88 或更新版本。

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/test-install.sh
python website/scripts/check_site.py
node --check website/app.js
node --check website/docs/docs.js
```

## 文档与许可证

- [产品网站](https://a3s-lab.github.io/Gateway/)
- [稳定文档](https://a3s-lab.github.io/Gateway/docs/)
- [开发文档](https://a3s-lab.github.io/Gateway/docs/next/)
- [发布流程](RELEASING.md)
- [变更日志](CHANGELOG.md)
- [路线图](ROADMAP.md)
- [分布式推理路由](docs/distributed-inference-routing.md)

以 [MIT License](LICENSE) 授权。
