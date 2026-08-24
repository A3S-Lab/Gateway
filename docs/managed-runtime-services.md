# Managed Runtime Service lifecycle

## Status and boundary

Managed Runtime Service routing is a Gateway foundation for embedded A3S
hosts. It is not an ACL mutation API, a public control-plane endpoint, or a
claim that the complete A3S Use and A3S Code package workflow is production
ready.

The host owns Runtime provisioning and package authorization. Gateway owns the
private data-plane route, health verification, admission closure, accepted-call
drain, and exact route removal. Streamable HTTP MCP initialization remains a
host responsibility and must run through the returned private Gateway endpoint
before the host publishes MCP readiness.

## Construction requirements

Create the embedded Gateway with
`Gateway::with_managed_service_state` or
`Gateway::with_middlewares_and_managed_service_state`.

- The state path must be an absolute normalized file path, separate from the managed
  snapshot journal and usage spool.
- Existing state must be a bounded regular non-symlink file. On Unix it must
  not be accessible by group or other users. New files are published with mode
  `0600`, an atomic rename, file synchronization, and parent-directory
  synchronization.
- The selected entrypoint must be cleartext HTTP on a positive loopback socket.
  Gateway rejects entrypoint replacement until every binding that owns it has
  been removed. Another maximum-priority router cannot share that entrypoint
  while a managed route is present.
- The Runtime upstream must be a positive loopback TCP socket distinct from
  the selected Gateway entrypoint.
- Service and health paths must be canonical absolute HTTP paths.
- Bind and lifecycle operation keys use canonical `sha256:<lowercase-hex>`
  identities.
- Each target binds a non-nil target UUID, one canonical Runtime unit ID, and a
  positive exact generation.

The base standalone ACL or Cloud-managed snapshot remains the desired-state
authority. Gateway injects the managed routes as a separate durable overlay and
preserves that overlay across ordinary reloads and managed snapshot reloads.

## Lifecycle contract

| Operation | Durable and live effect |
| --- | --- |
| `bind_managed_service` | Persists `Binding`, installs or replays the exact opaque route, verifies the configured health path through Gateway before the deadline, persists `Ready`, and returns the private endpoint plus receipt identity. Reusing the bind key with changed entrypoint, target, upstream, path, or health identity fails closed. |
| `managed_service_status` | Returns only the exact receipt identity and bounded phase. A target-generation mismatch fails instead of selecting another route. |
| `drain_managed_service` | Persists the exact drain key, closes generation admission, atomically hides the route, and waits for every already admitted HTTP body, gRPC response, or WebSocket to release its backend guard. A timed-out drain remains replayable and cannot forget the hidden generation. |
| `remove_managed_service` | Removes only an exact `Drained` receipt. Repeating removal after absence succeeds without touching another generation. |

The durable phases are `Binding`, `Ready`, `Draining`, and `Drained`. Gateway
loads and validates the complete state before opening listeners. `Binding` and
`Ready` routes are restored; `Draining` and `Drained` routes stay hidden. A
replayed bind retains the same `gateway:managed-services/<sha256>` identity
after process restart.

## Embedded example

```rust,no_run
use a3s_gateway::config::{GatewayConfig, ManagedTargetConfig};
use a3s_gateway::managed_service::{
    ManagedServiceBindingRequest, ManagedServiceHealthCheck,
};
use a3s_gateway::{Gateway, Result};
use std::time::Duration;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let config = GatewayConfig::from_file("gateway.acl").await?;
    let gateway = Gateway::with_managed_service_state(
        config,
        "/var/lib/a3s/gateway/managed-runtime-services.json",
    )?;
    gateway.start().await?;

    let request = ManagedServiceBindingRequest::new(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "plugins",
        ManagedTargetConfig {
            target_id: Uuid::parse_str("018f0000-0000-7000-8000-000000000001")
                .expect("static UUID"),
            unit_id: "use:workspace-01:acme-search:mcp-query".to_string(),
            generation: 7,
        },
        "127.0.0.1:31337".parse().expect("static socket"),
        "/mcp",
        ManagedServiceHealthCheck::new("/healthz", 250, 500, 2, 3)?,
    )?;
    let deadline = Some(tokio::time::Instant::now() + Duration::from_secs(10));
    let binding = gateway.bind_managed_service(request, deadline).await?;

    // The trusted host negotiates MCP initialize or invokes the Tool Service
    // through binding.endpoint(), while durable receipts retain endpoint_ref().

    gateway
        .drain_managed_service(
            binding.identity(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            deadline,
        )
        .await?;
    gateway
        .remove_managed_service(
            binding.identity(),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            deadline,
        )
        .await?;
    gateway.shutdown().await;
    Ok(())
}
```

The state file is private lifecycle authority, not a user-editable
configuration file. Corrupt, oversized, linked, broadly readable, duplicate,
or identity-inconsistent state prevents Gateway startup.
