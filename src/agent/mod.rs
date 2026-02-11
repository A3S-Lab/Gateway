//! AI Agent Gateway — SafeClaw-specific extensions
//!
//! Provides multi-channel webhook ingestion, privacy-aware routing,
//! token metering, and conversation affinity for AI agent workloads.

pub mod affinity;
pub mod channel;
pub mod health_probe;
pub mod privacy_router;
pub mod token_meter;

pub use affinity::ConversationAffinity;
pub use channel::{ChannelMessage, ChannelType, WebhookHandler};
pub use health_probe::AgentHealthProbe;
pub use privacy_router::{PrivacyLevel, PrivacyRouter};
pub use token_meter::TokenMeter;
