# A3S Gateway — Technical Design

## 定位

对标 Traefik 核心能力 + AI Agent 网关扩展，作为 SafeClaw 的网络入口层。

---

## 一、Traefik 核心能力对标

### Traefik 架构三要素

```
Entrypoint → Router → Middleware → Service
(监听端口)   (路由匹配)  (请求变换)   (上游后端)
```

### 需要对标的能力清单

| Traefik 能力 | 优先级 | 说明 |
|-------------|--------|------|
| **Entrypoints** (多端口监听) | P0 | HTTP/HTTPS/TCP/UDP 多端口 |
| **HTTP Router** (Host/Path/Header 规则) | P0 | 规则引擎匹配请求 |
| **TCP Router** (SNI/HostSNI 规则) | P1 | 原始 TCP 代理 |
| **UDP Router** | P2 | UDP 代理 |
| **Load Balancer** (RR/Weighted/WRR) | P0 | 多后端负载均衡 |
| **Health Check** (主动/被动) | P0 | 后端健康探测 |
| **TLS Termination** | P0 | HTTPS 终止 + 证书管理 |
| **ACME/Let's Encrypt** | P1 | 自动证书签发 |
| **WebSocket Proxy** | P0 | WS/WSS 透传 |
| **gRPC Proxy** | P1 | gRPC 负载均衡 |
| **SSE/Streaming Proxy** | P0 | 流式响应透传 (LLM 输出) |
| **Middleware: Auth** | P0 | BasicAuth / API Key / JWT |
| **Middleware: RateLimit** | P0 | 令牌桶限流 |
| **Middleware: Headers** | P0 | 请求/响应头修改 |
| **Middleware: Retry** | P1 | 失败重试 |
| **Middleware: CircuitBreaker** | P1 | 熔断器 |
| **Middleware: StripPrefix** | P0 | 路径前缀剥离 |
| **Middleware: CORS** | P0 | 跨域处理 |
| **Middleware: Compress** | P2 | gzip/brotli 压缩 |
| **Middleware: IPAllowList** | P1 | IP 白名单 |
| **Provider: File** | P0 | TOML/YAML 文件配置 |
| **Provider: Docker/K8s** | P3 | 容器服务发现 (远期) |
| **Provider: DNS** | P2 | DNS 服务发现 |
| **Hot Reload** | P0 | 配置热更新 |
| **Metrics** (Prometheus) | P1 | 指标暴露 |
| **Access Log** | P1 | 结构化访问日志 |
| **Tracing** (OpenTelemetry) | P2 | 分布式追踪 |
| **Dashboard/API** | P2 | 管理面板 |

---

## 二、AI Agent 网关扩展 (SafeClaw 专属)

SafeClaw 当前网络需求分析：

```
外部流量                    SafeClaw 内部
─────────                  ──────────────
Telegram Webhook ──┐
Slack Webhook ─────┤
Discord Webhook ───┤       ┌──────────────┐
Feishu Webhook ────┼──→ Gateway ──→ │ SafeClaw Core │
DingTalk Webhook ──┤       │              │ (Session/Privacy/Memory)
WeCom Webhook ─────┤       └──────┬───────┘
WebChat (WS) ──────┘              │
                                  │ vsock:4089 (encrypted)
                              ┌───▼───────────┐
                              │ TEE Agent     │
                              │ (A3S Box VM)  │
                              └───────────────┘
```

### 需要新增的 AI Agent 能力

| 能力 | 说明 |
|------|------|
| **Channel Webhook Ingestion** | 统一接收 7 个平台的 webhook，标准化为内部消息格式 |
| **Privacy-Aware Routing** | 根据隐私分类结果决定路由到本地还是 TEE |
| **SSE/Streaming Proxy** | LLM 流式输出透传给客户端 |
| **Token Metering** | 按 agent/user/session 统计和限制 token 用量 |
| **Conversation Affinity** | 多轮对话粘性会话 (同一会话路由到同一后端) |
| **Agent Health Probe** | 探测 AI agent 是否可用 (模型加载状态) |
| **Request Priority** | 根据消息类型/用户等级设置请求优先级 |

---

## 三、技术架构

### 分层设计

```
┌─────────────────────────────────────────────────────────────┐
│                        Entrypoints                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ HTTP:80  │ │HTTPS:443 │ │ TCP:9000 │ │ UDP:9001 │      │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
│       └─────────────┴────────────┴─────────────┘            │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │                    TLS Termination                    │   │
│  │              (rustls / native-tls)                    │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │                   Router Layer                        │   │
│  │                                                       │   │
│  │  HTTP Router:  Host() && Path() && Headers()         │   │
│  │  TCP Router:   HostSNI()                             │   │
│  │  UDP Router:   port-based                            │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │              Middleware Pipeline                       │   │
│  │                                                       │   │
│  │  ┌─────┐ ┌────────┐ ┌──────┐ ┌─────┐ ┌───────────┐ │   │
│  │  │Auth │→│RateLimit│→│CORS  │→│Strip│→│TokenMeter │ │   │
│  │  └─────┘ └────────┘ └──────┘ └─────┘ └───────────┘ │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │                  Service Layer                        │   │
│  │                                                       │   │
│  │  Load Balancer (RR / Weighted / LeastConn)           │   │
│  │  Health Check  (Active / Passive)                    │   │
│  │  Circuit Breaker                                     │   │
│  │  Conversation Affinity (sticky session)              │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
└─────────────────────────┼───────────────────────────────────┘
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
       ┌────────┐   ┌────────┐   ┌──────────┐
       │HTTP    │   │gRPC    │   │TEE Agent │
       │Backend │   │Backend │   │(vsock)   │
       └────────┘   └────────┘   └──────────┘
```

### 模块划分

```
gateway/
├── Cargo.toml
├── src/
│   ├── lib.rs                # 公开 API
│   ├── main.rs               # CLI 入口
│   ├── error.rs              # 错误类型
│   │
│   ├── config/               # 配置层
│   │   ├── mod.rs            # GatewayConfig 总配置
│   │   ├── entrypoint.rs     # Entrypoint 配置
│   │   ├── router.rs         # Router 规则配置
│   │   ├── service.rs        # Service 后端配置
│   │   ├── middleware.rs     # Middleware 配置
│   │   └── provider.rs       # Provider 配置 (file/dns)
│   │
│   ├── entrypoint/           # 入口监听层
│   │   ├── mod.rs
│   │   ├── http.rs           # HTTP/HTTPS 监听
│   │   ├── tcp.rs            # TCP 监听
│   │   └── udp.rs            # UDP 监听
│   │
│   ├── router/               # 路由层
│   │   ├── mod.rs
│   │   ├── rule.rs           # 规则引擎 (Host/Path/Header/Query 匹配)
│   │   ├── http.rs           # HTTP 路由器
│   │   ├── tcp.rs            # TCP 路由器 (SNI)
│   │   └── priority.rs       # 路由优先级
│   │
│   ├── middleware/            # 中间件层
│   │   ├── mod.rs            # Middleware trait + Pipeline
│   │   ├── auth.rs           # BasicAuth / APIKey / JWT
│   │   ├── rate_limit.rs     # 令牌桶限流
│   │   ├── cors.rs           # CORS
│   │   ├── headers.rs        # 请求/响应头修改
│   │   ├── strip_prefix.rs   # 路径前缀剥离
│   │   ├── retry.rs          # 重试
│   │   ├── circuit_breaker.rs # 熔断
│   │   ├── ip_allow.rs       # IP 白名单
│   │   └── compress.rs       # 压缩
│   │
│   ├── service/              # 服务层
│   │   ├── mod.rs
│   │   ├── backend.rs        # Backend 抽象 (HTTP/gRPC/TCP)
│   │   ├── load_balancer.rs  # 负载均衡策略
│   │   ├── health_check.rs   # 健康检查
│   │   └── sticky.rs         # 会话粘性
│   │
│   ├── proxy/                # 代理层 (实际转发)
│   │   ├── mod.rs
│   │   ├── http.rs           # HTTP/HTTPS 反向代理
│   │   ├── websocket.rs      # WebSocket 代理
│   │   ├── grpc.rs           # gRPC 代理
│   │   ├── tcp.rs            # TCP 代理
│   │   ├── udp.rs            # UDP 代理
│   │   └── stream.rs         # SSE/Streaming 代理
│   │
│   ├── tls/                  # TLS 层
│   │   ├── mod.rs
│   │   ├── config.rs         # 证书配置
│   │   └── acme.rs           # Let's Encrypt 自动签发
│   │
│   ├── provider/             # 配置提供者
│   │   ├── mod.rs            # Provider trait
│   │   ├── file.rs           # TOML/YAML 文件 + 热重载 (inotify/kqueue)
│   │   └── dns.rs            # DNS 服务发现
│   │
│   ├── agent/                # AI Agent 扩展 (SafeClaw 专属)
│   │   ├── mod.rs
│   │   ├── channel.rs        # 多平台 Webhook 标准化
│   │   ├── privacy_router.rs # 隐私感知路由
│   │   ├── token_meter.rs    # Token 用量统计
│   │   └── affinity.rs       # 对话粘性会话
│   │
│   └── observability/        # 可观测性
│       ├── mod.rs
│       ├── metrics.rs        # Prometheus 指标
│       ├── access_log.rs     # 结构化访问日志
│       └── tracing.rs        # OpenTelemetry 追踪
```

### 核心依赖选型

| 用途 | 库 | 理由 |
|------|-----|------|
| HTTP Server | `hyper` 1.x + `axum` 0.7 | 高性能，生态成熟 |
| TLS | `rustls` + `tokio-rustls` | 纯 Rust，无 OpenSSL 依赖 |
| ACME | `instant-acme` | 轻量 Let's Encrypt 客户端 |
| TCP/UDP | `tokio::net` | 原生异步 |
| gRPC | `tonic` | Rust gRPC 标准 |
| WebSocket | `tokio-tungstenite` | 成熟稳定 |
| HTTP Client | `hyper-util` + `reqwest` | 代理转发用 hyper，外部调用用 reqwest |
| Config Watch | `notify` | 跨平台文件监听 (inotify/kqueue/FSEvents) |
| Rule Parsing | 自研 | Traefik 风格规则语法 `Host() && PathPrefix()` |
| Metrics | `metrics` + `metrics-exporter-prometheus` | Prometheus 生态 |
| Tracing | `opentelemetry` + `tracing-opentelemetry` | OTel 标准 |

---

## 四、配置格式设计

对标 Traefik 的 TOML 配置风格，但更简洁：

```toml
# gateway.toml

# ============ 入口点 ============
[entrypoints.web]
address = "0.0.0.0:80"

[entrypoints.websecure]
address = "0.0.0.0:443"
[entrypoints.websecure.tls]
cert_file = "/etc/certs/cert.pem"
key_file = "/etc/certs/key.pem"
# acme = true  # 启用 Let's Encrypt

[entrypoints.tcp]
address = "0.0.0.0:9000"
protocol = "tcp"

# ============ HTTP 路由 ============
[routers.safeclaw-api]
rule = "Host(`api.safeclaw.io`) && PathPrefix(`/v1`)"
entrypoints = ["websecure"]
service = "safeclaw-core"
middlewares = ["auth-jwt", "rate-limit-api"]

[routers.webhook-telegram]
rule = "Path(`/webhook/telegram`)"
entrypoints = ["websecure"]
service = "safeclaw-core"
middlewares = ["verify-telegram"]

[routers.webchat-ws]
rule = "Path(`/ws`)"
entrypoints = ["websecure"]
service = "safeclaw-core"
# WebSocket 自动检测 Upgrade 头

[routers.llm-stream]
rule = "PathPrefix(`/agent/chat`)"
entrypoints = ["websecure"]
service = "safeclaw-agent"
middlewares = ["auth-jwt", "token-meter"]

# ============ TCP 路由 ============
[routers.grpc-internal]
rule = "HostSNI(`*`)"
entrypoints = ["tcp"]
service = "grpc-backend"

# ============ 服务 ============
[services.safeclaw-core.load_balancer]
strategy = "round-robin"
health_check = { path = "/health", interval = "10s" }
[[services.safeclaw-core.load_balancer.servers]]
url = "http://127.0.0.1:18790"

[services.safeclaw-agent.load_balancer]
strategy = "least-connections"
sticky = { cookie = "agent_session" }
health_check = { path = "/health", interval = "5s" }
[[services.safeclaw-agent.load_balancer.servers]]
url = "http://127.0.0.1:18791"
[[services.safeclaw-agent.load_balancer.servers]]
url = "http://127.0.0.1:18792"

[services.grpc-backend.load_balancer]
strategy = "round-robin"
[[services.grpc-backend.load_balancer.servers]]
url = "h2c://127.0.0.1:50051"

# ============ 中间件 ============
[middlewares.auth-jwt]
type = "jwt"
secret = "${JWT_SECRET}"
header = "Authorization"

[middlewares.rate-limit-api]
type = "rate-limit"
rate = 100
burst = 50

[middlewares.token-meter]
type = "token-meter"
max_tokens_per_minute = 10000
header = "X-Token-Count"

[middlewares.verify-telegram]
type = "custom-header"
header = "X-Telegram-Bot-Api-Secret-Token"
value = "${TELEGRAM_SECRET}"

# ============ 配置提供者 ============
[providers.file]
watch = true
directory = "/etc/gateway/conf.d/"

# ============ 可观测性 ============
[metrics]
prometheus = { entrypoint = "web", path = "/metrics" }

[access_log]
format = "json"
path = "/var/log/gateway/access.log"

[tracing]
otlp_endpoint = "http://localhost:4317"
```

---

## 五、实现阶段

### Phase 1: Core Proxy (MVP) — 预计 2-3 周

**目标**: 可用的多协议反向代理

```
P1a: 基础骨架
├── TOML 配置解析 (entrypoints/routers/services/middlewares)
├── HTTP Entrypoint (hyper 监听)
├── HTTP Router (Host/Path/Header 规则引擎)
├── HTTP 反向代理 (请求转发 + 响应回传)
├── WebSocket 代理 (Upgrade 检测 + 双向透传)
└── SSE/Streaming 代理 (chunked transfer 透传)

P1b: 负载均衡 + 健康检查
├── Round-Robin 负载均衡
├── Weighted Round-Robin
├── Least-Connections
├── Active Health Check (定时 HTTP 探测)
└── Passive Health Check (错误计数自动摘除)

P1c: 中间件
├── Middleware trait + Pipeline 组合
├── Auth (API Key / BasicAuth)
├── RateLimit (令牌桶)
├── CORS
├── Headers (Add/Set/Remove)
├── StripPrefix
└── Hot Reload (notify 文件监听)
```

### Phase 2: TLS + TCP/UDP — 预计 1-2 周

```
├── TLS Termination (rustls)
├── ACME/Let's Encrypt (instant-acme)
├── TCP Entrypoint + Router (SNI)
├── TCP Proxy (双向字节流透传)
├── UDP Entrypoint + Router
├── UDP Proxy
└── gRPC Proxy (HTTP/2 + h2c)
```

### Phase 3: AI Agent Gateway — 预计 2 周

```
├── Channel Webhook 标准化 (7 平台 → 统一消息格式)
├── Privacy-Aware Router (隐私分类 → 路由决策)
├── Token Metering Middleware (token 用量统计 + 限制)
├── Conversation Affinity (cookie/header 粘性)
├── Agent Health Probe (模型加载状态探测)
└── Request Priority (消息类型/用户等级 → 优先级)
```

### Phase 4: Observability — 预计 1 周

```
├── Prometheus Metrics Endpoint
├── Structured Access Log (JSON)
├── OpenTelemetry Tracing
├── JWT / OAuth2 Auth Middleware
├── IP AllowList / BlockList
├── Circuit Breaker
└── Retry Middleware
```

---

## 六、与 SafeClaw 的集成方式

### 当前 SafeClaw 架构

```
SafeClaw 自己处理所有网络:
  Telegram Webhook → SafeClaw HTTP Server (axum:18790)
  Slack Webhook    → SafeClaw HTTP Server
  WebChat WS       → SafeClaw HTTP Server
  ...
```

### 目标架构

```
所有外部流量经过 Gateway:
  Telegram Webhook ─┐
  Slack Webhook ────┤
  WebChat WS ───────┼→ A3S Gateway (:443) ──→ SafeClaw Core (:18790)
  API Requests ─────┤                    ├──→ SafeClaw Agent (:18791)
  gRPC ─────────────┘                    └──→ TEE Agent (vsock:4089)
```

SafeClaw 只需要关注业务逻辑，网络入口、TLS、限流、认证、负载均衡全部交给 Gateway。

---

## 七、关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| HTTP 框架 | hyper 直接用，不套 axum | 代理需要底层控制 (Upgrade, streaming, h2c) |
| TLS 实现 | rustls | 纯 Rust，无系统依赖，安全 |
| 规则语法 | Traefik 兼容 `Host() && PathPrefix()` | 降低学习成本，生态兼容 |
| 配置格式 | TOML (主) + YAML (可选) | Rust 生态 TOML 一等公民 |
| 热重载 | notify (inotify/kqueue) | 跨平台，零轮询 |
| 代理模式 | L4 (TCP/UDP) + L7 (HTTP/gRPC/WS) | 覆盖所有场景 |
