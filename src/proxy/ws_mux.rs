//! WebSocket multiplexing — multiplex multiple logical channels over a single WebSocket
//!
//! Allows clients to subscribe to named channels and receive messages
//! routed to the correct channel. Each frame carries a channel ID prefix.
//!
//! Wire format: `<channel_id>:<payload>`
//!
//! Control messages:
//! - `_sub:<channel_id>` — subscribe to a channel
//! - `_unsub:<channel_id>` — unsubscribe from a channel
//! - `_ping` / `_pong` — keepalive

#![allow(dead_code)]
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Maximum number of channels per connection
const MAX_CHANNELS: usize = 64;

/// Broadcast channel buffer size
const CHANNEL_BUFFER: usize = 256;

/// A multiplexed WebSocket channel hub
pub struct WsMuxHub {
    /// Named broadcast channels
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<MuxMessage>>>>,
}

/// A message in a multiplexed channel
#[derive(Debug, Clone)]
pub struct MuxMessage {
    /// Channel this message belongs to
    pub channel: String,
    /// Message payload
    pub payload: String,
}

impl WsMuxHub {
    /// Create a new multiplexing hub
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a broadcast channel
    pub async fn get_or_create_channel(&self, name: &str) -> broadcast::Sender<MuxMessage> {
        let mut channels = self.channels.write().await;
        if let Some(tx) = channels.get(name) {
            if tx.receiver_count() > 0 {
                return tx.clone();
            }
        }
        let (tx, _) = broadcast::channel(CHANNEL_BUFFER);
        channels.insert(name.to_string(), tx.clone());
        tx
    }

    /// Subscribe to a channel, returns a receiver
    pub async fn subscribe(&self, name: &str) -> broadcast::Receiver<MuxMessage> {
        let tx = self.get_or_create_channel(name).await;
        tx.subscribe()
    }

    /// Publish a message to a channel
    pub async fn publish(&self, channel: &str, payload: String) -> usize {
        let channels = self.channels.read().await;
        if let Some(tx) = channels.get(channel) {
            tx.send(MuxMessage {
                channel: channel.to_string(),
                payload,
            })
            .unwrap_or(0)
        } else {
            0
        }
    }

    /// List active channel names
    pub async fn channel_names(&self) -> Vec<String> {
        self.channels.read().await.keys().cloned().collect()
    }

    /// Remove channels with no subscribers
    pub async fn cleanup_empty_channels(&self) {
        let mut channels = self.channels.write().await;
        channels.retain(|_, tx| tx.receiver_count() > 0);
    }
}

impl Default for WsMuxHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-connection multiplexer state
pub struct WsMuxConnection {
    /// Channels this connection is subscribed to
    subscriptions: HashSet<String>,
    /// Reference to the hub
    hub: Arc<WsMuxHub>,
}

impl WsMuxConnection {
    /// Create a new connection-level mux state
    pub fn new(hub: Arc<WsMuxHub>) -> Self {
        Self {
            subscriptions: HashSet::new(),
            hub,
        }
    }

    /// Process an incoming text frame from the client.
    /// Returns an optional response to send back.
    pub async fn process_message(&mut self, text: &str) -> Option<String> {
        // Control messages
        if let Some(channel) = text.strip_prefix("_sub:") {
            return Some(self.subscribe(channel.trim()).await);
        }
        if let Some(channel) = text.strip_prefix("_unsub:") {
            return Some(self.unsubscribe(channel.trim()));
        }
        if text == "_ping" {
            return Some("_pong".to_string());
        }
        if text == "_list" {
            let channels: Vec<&String> = self.subscriptions.iter().collect();
            return Some(format!("_channels:{}", serde_json::json!(channels)));
        }

        // Data message: channel:payload
        if let Some((channel, payload)) = text.split_once(':') {
            if self.subscriptions.contains(channel) {
                let sent = self.hub.publish(channel, payload.to_string()).await;
                tracing::debug!(channel = channel, receivers = sent, "Mux message published");
            }
            return None;
        }

        // Unknown format
        Some("_error:invalid message format".to_string())
    }

    /// Subscribe to a channel
    async fn subscribe(&mut self, channel: &str) -> String {
        if self.subscriptions.len() >= MAX_CHANNELS {
            return format!("_error:max channels ({}) reached", MAX_CHANNELS);
        }
        if self.subscriptions.contains(channel) {
            return format!("_ok:already subscribed to {}", channel);
        }
        // Ensure channel exists in hub
        let _ = self.hub.get_or_create_channel(channel).await;
        self.subscriptions.insert(channel.to_string());
        format!("_ok:subscribed to {}", channel)
    }

    /// Unsubscribe from a channel
    fn unsubscribe(&mut self, channel: &str) -> String {
        if self.subscriptions.remove(channel) {
            format!("_ok:unsubscribed from {}", channel)
        } else {
            format!("_ok:not subscribed to {}", channel)
        }
    }

    /// Get the set of subscribed channels
    pub fn subscriptions(&self) -> &HashSet<String> {
        &self.subscriptions
    }

    /// Check if subscribed to a channel
    pub fn is_subscribed(&self, channel: &str) -> bool {
        self.subscriptions.contains(channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- WsMuxHub ---

    #[tokio::test]
    async fn test_hub_create_channel() {
        let hub = WsMuxHub::new();
        let _tx = hub.get_or_create_channel("test").await;
        let names = hub.channel_names().await;
        assert!(names.contains(&"test".to_string()));
    }

    #[tokio::test]
    async fn test_hub_subscribe_and_publish() {
        let hub = WsMuxHub::new();
        let mut rx = hub.subscribe("events").await;
        let sent = hub.publish("events", "hello".to_string()).await;
        assert_eq!(sent, 1);
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.channel, "events");
        assert_eq!(msg.payload, "hello");
    }

    #[tokio::test]
    async fn test_hub_publish_no_subscribers() {
        let hub = WsMuxHub::new();
        let sent = hub.publish("empty", "hello".to_string()).await;
        assert_eq!(sent, 0);
    }

    #[tokio::test]
    async fn test_hub_multiple_subscribers() {
        let hub = WsMuxHub::new();
        let mut rx1 = hub.subscribe("ch").await;
        let mut rx2 = hub.subscribe("ch").await;
        hub.publish("ch", "msg".to_string()).await;
        assert_eq!(rx1.recv().await.unwrap().payload, "msg");
        assert_eq!(rx2.recv().await.unwrap().payload, "msg");
    }

    #[tokio::test]
    async fn test_hub_cleanup_empty() {
        let hub = WsMuxHub::new();
        let _tx = hub.get_or_create_channel("orphan").await;
        // No subscribers, cleanup should remove it
        hub.cleanup_empty_channels().await;
        // Channel with no receivers gets cleaned
        let names = hub.channel_names().await;
        assert!(!names.contains(&"orphan".to_string()));
    }

    #[tokio::test]
    async fn test_hub_default() {
        let hub = WsMuxHub::default();
        assert!(hub.channel_names().await.is_empty());
    }

    // --- WsMuxConnection ---

    #[tokio::test]
    async fn test_conn_subscribe() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        let resp = conn.process_message("_sub:events").await;
        assert!(resp.unwrap().contains("subscribed to events"));
        assert!(conn.is_subscribed("events"));
    }

    #[tokio::test]
    async fn test_conn_unsubscribe() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        conn.process_message("_sub:events").await;
        let resp = conn.process_message("_unsub:events").await;
        assert!(resp.unwrap().contains("unsubscribed from events"));
        assert!(!conn.is_subscribed("events"));
    }

    #[tokio::test]
    async fn test_conn_unsubscribe_not_subscribed() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        let resp = conn.process_message("_unsub:nope").await;
        assert!(resp.unwrap().contains("not subscribed"));
    }

    #[tokio::test]
    async fn test_conn_ping_pong() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        let resp = conn.process_message("_ping").await;
        assert_eq!(resp.unwrap(), "_pong");
    }

    #[tokio::test]
    async fn test_conn_list_channels() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        conn.process_message("_sub:ch1").await;
        conn.process_message("_sub:ch2").await;
        let resp = conn.process_message("_list").await.unwrap();
        assert!(resp.starts_with("_channels:"));
        assert!(resp.contains("ch1"));
        assert!(resp.contains("ch2"));
    }

    #[tokio::test]
    async fn test_conn_data_message() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub.clone());
        conn.process_message("_sub:data").await;

        // Subscribe a receiver to verify publish
        let mut rx = hub.subscribe("data").await;

        // Send data message
        let resp = conn.process_message("data:hello world").await;
        assert!(resp.is_none()); // Data messages don't produce a response

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.payload, "hello world");
    }

    #[tokio::test]
    async fn test_conn_data_message_not_subscribed() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        // Not subscribed to "data", message should be silently ignored
        let resp = conn.process_message("data:hello").await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn test_conn_invalid_message() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        let resp = conn.process_message("no-colon-here").await;
        assert!(resp.unwrap().contains("_error"));
    }

    #[tokio::test]
    async fn test_conn_max_channels() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        for i in 0..MAX_CHANNELS {
            conn.process_message(&format!("_sub:ch{}", i)).await;
        }
        assert_eq!(conn.subscriptions().len(), MAX_CHANNELS);
        let resp = conn.process_message("_sub:overflow").await;
        assert!(resp.unwrap().contains("max channels"));
        assert!(!conn.is_subscribed("overflow"));
    }

    #[tokio::test]
    async fn test_conn_duplicate_subscribe() {
        let hub = Arc::new(WsMuxHub::new());
        let mut conn = WsMuxConnection::new(hub);
        conn.process_message("_sub:ch").await;
        let resp = conn.process_message("_sub:ch").await;
        assert!(resp.unwrap().contains("already subscribed"));
        assert_eq!(conn.subscriptions().len(), 1);
    }

    // --- MuxMessage ---

    #[test]
    fn test_mux_message_clone() {
        let msg = MuxMessage {
            channel: "test".to_string(),
            payload: "data".to_string(),
        };
        let cloned = msg.clone();
        assert_eq!(cloned.channel, "test");
        assert_eq!(cloned.payload, "data");
    }
}
