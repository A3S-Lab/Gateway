//! Scaling module for standalone serverless serving.
//!
//! Provides autoscaling decisions, request buffering during cold starts,
//! concurrency limiting, static revision traffic splitting, and pluggable
//! scale executors.

pub mod autoscaler;
pub mod buffer;
pub mod concurrency;
pub mod executor;
#[cfg(feature = "kube")]
pub mod kubernetes_executor;
pub mod revision;
