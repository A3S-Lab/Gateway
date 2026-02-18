//! Scaling module — Knative-style serverless serving
//!
//! Provides autoscaling decisions, request buffering during cold starts,
//! concurrency limiting, revision-based traffic splitting, gradual rollouts,
//! and pluggable scale executors.

pub mod autoscaler;
pub mod buffer;
pub mod concurrency;
pub mod executor;
pub mod revision;
pub mod rollout;
