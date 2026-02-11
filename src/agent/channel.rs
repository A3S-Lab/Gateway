//! Multi-channel webhook handler — standardizes messages from 7 platforms
//!
//! Converts platform-specific webhook payloads into a unified ChannelMessage
//! format for downstream processing.

use serde::{Deserialize, Serialize};

/// Supported messaging channel types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelType {
    Telegram,
    Slack,
    Discord,
    Feishu,
    DingTalk,
    WeCom,
    WebChat,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Telegram => write!(f, "telegram"),
            Self::Slack => write!(f, "slack"),
            Self::Discord => write!(f, "discord"),
            Self::Feishu => write!(f, "feishu"),
            Self::DingTalk => write!(f, "dingtalk"),
            Self::WeCom => write!(f, "wecom"),
            Self::WebChat => write!(f, "webchat"),
        }
    }
}

impl ChannelType {
    /// Parse channel type from a webhook path segment
    pub fn from_path(path: &str) -> Option<Self> {
        match path.to_lowercase().as_str() {
            "telegram" => Some(Self::Telegram),
            "slack" => Some(Self::Slack),
            "discord" => Some(Self::Discord),
            "feishu" | "lark" => Some(Self::Feishu),
            "dingtalk" => Some(Self::DingTalk),
            "wecom" | "wechat" => Some(Self::WeCom),
            "webchat" | "web" => Some(Self::WebChat),
            _ => None,
        }
    }
}

/// Unified channel message — normalized from any platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMessage {
    /// Unique message ID (platform-specific or generated)
    pub id: String,
    /// Source channel type
    pub channel: ChannelType,
    /// Chat/conversation ID on the platform
    pub chat_id: String,
    /// Sender user ID on the platform
    pub sender_id: String,
    /// Sender display name (if available)
    pub sender_name: Option<String>,
    /// Message text content
    pub content: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Whether this is a reply to another message
    pub reply_to: Option<String>,
    /// Raw platform-specific payload (for passthrough)
    pub raw: Option<serde_json::Value>,
}

/// Webhook handler — parses platform-specific payloads into ChannelMessage
pub struct WebhookHandler;

impl WebhookHandler {
    /// Parse a webhook payload from the given channel type
    pub fn parse(
        channel: &ChannelType,
        body: &[u8],
    ) -> Result<ChannelMessage, String> {
        let json: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| format!("Invalid JSON payload: {}", e))?;

        match channel {
            ChannelType::Telegram => Self::parse_telegram(&json),
            ChannelType::Slack => Self::parse_slack(&json),
            ChannelType::Discord => Self::parse_discord(&json),
            ChannelType::Feishu => Self::parse_feishu(&json),
            ChannelType::DingTalk => Self::parse_dingtalk(&json),
            ChannelType::WeCom => Self::parse_wecom(&json),
            ChannelType::WebChat => Self::parse_webchat(&json),
        }
    }

    fn parse_telegram(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        let message = json.get("message").unwrap_or(json);
        Ok(ChannelMessage {
            id: message
                .get("message_id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            channel: ChannelType::Telegram,
            chat_id: message
                .get("chat")
                .and_then(|c| c.get("id"))
                .and_then(|v| v.as_i64())
                .map(|v| v.to_string())
                .unwrap_or_default(),
            sender_id: message
                .get("from")
                .and_then(|f| f.get("id"))
                .and_then(|v| v.as_i64())
                .map(|v| v.to_string())
                .unwrap_or_default(),
            sender_name: message
                .get("from")
                .and_then(|f| f.get("first_name"))
                .and_then(|v| v.as_str())
                .map(String::from),
            content: message
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: message
                .get("date")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                * 1000,
            reply_to: message
                .get("reply_to_message")
                .and_then(|r| r.get("message_id"))
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string()),
            raw: Some(json.clone()),
        })
    }

    fn parse_slack(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        let event = json.get("event").unwrap_or(json);
        Ok(ChannelMessage {
            id: event
                .get("client_msg_id")
                .or_else(|| event.get("ts"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            channel: ChannelType::Slack,
            chat_id: event
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_id: event
                .get("user")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_name: None,
            content: event
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: event
                .get("ts")
                .and_then(|v| v.as_str())
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
                * 1000,
            reply_to: event
                .get("thread_ts")
                .and_then(|v| v.as_str())
                .map(String::from),
            raw: Some(json.clone()),
        })
    }

    fn parse_discord(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        Ok(ChannelMessage {
            id: json
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            channel: ChannelType::Discord,
            chat_id: json
                .get("channel_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_id: json
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_name: json
                .get("author")
                .and_then(|a| a.get("username"))
                .and_then(|v| v.as_str())
                .map(String::from),
            content: json
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: 0, // Discord uses snowflake IDs
            reply_to: json
                .get("message_reference")
                .and_then(|r| r.get("message_id"))
                .and_then(|v| v.as_str())
                .map(String::from),
            raw: Some(json.clone()),
        })
    }

    fn parse_feishu(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        let event = json
            .get("event")
            .and_then(|e| e.get("message"))
            .unwrap_or(json);
        Ok(ChannelMessage {
            id: event
                .get("message_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            channel: ChannelType::Feishu,
            chat_id: event
                .get("chat_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_id: json
                .get("event")
                .and_then(|e| e.get("sender"))
                .and_then(|s| s.get("sender_id"))
                .and_then(|s| s.get("open_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_name: None,
            content: event
                .get("content")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                .and_then(|c| c.get("text").and_then(|v| v.as_str()).map(String::from))
                .unwrap_or_default(),
            timestamp: event
                .get("create_time")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0),
            reply_to: event
                .get("parent_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            raw: Some(json.clone()),
        })
    }

    fn parse_dingtalk(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        Ok(ChannelMessage {
            id: json
                .get("msgId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            channel: ChannelType::DingTalk,
            chat_id: json
                .get("conversationId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_id: json
                .get("senderStaffId")
                .or_else(|| json.get("senderId"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_name: json
                .get("senderNick")
                .and_then(|v| v.as_str())
                .map(String::from),
            content: json
                .get("text")
                .and_then(|t| t.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: json
                .get("createAt")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            reply_to: None,
            raw: Some(json.clone()),
        })
    }

    fn parse_wecom(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        Ok(ChannelMessage {
            id: json
                .get("MsgId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            channel: ChannelType::WeCom,
            chat_id: json
                .get("FromUserName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_id: json
                .get("FromUserName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_name: None,
            content: json
                .get("Content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: json
                .get("CreateTime")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                * 1000,
            reply_to: None,
            raw: Some(json.clone()),
        })
    }

    fn parse_webchat(json: &serde_json::Value) -> Result<ChannelMessage, String> {
        Ok(ChannelMessage {
            id: json
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().leak())
                .to_string(),
            channel: ChannelType::WebChat,
            chat_id: json
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_id: json
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sender_name: json
                .get("user_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            content: json
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: json
                .get("timestamp")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            reply_to: None,
            raw: Some(json.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_type_display() {
        assert_eq!(ChannelType::Telegram.to_string(), "telegram");
        assert_eq!(ChannelType::Slack.to_string(), "slack");
        assert_eq!(ChannelType::Discord.to_string(), "discord");
        assert_eq!(ChannelType::Feishu.to_string(), "feishu");
        assert_eq!(ChannelType::DingTalk.to_string(), "dingtalk");
        assert_eq!(ChannelType::WeCom.to_string(), "wecom");
        assert_eq!(ChannelType::WebChat.to_string(), "webchat");
    }

    #[test]
    fn test_channel_type_from_path() {
        assert_eq!(ChannelType::from_path("telegram"), Some(ChannelType::Telegram));
        assert_eq!(ChannelType::from_path("slack"), Some(ChannelType::Slack));
        assert_eq!(ChannelType::from_path("discord"), Some(ChannelType::Discord));
        assert_eq!(ChannelType::from_path("feishu"), Some(ChannelType::Feishu));
        assert_eq!(ChannelType::from_path("lark"), Some(ChannelType::Feishu));
        assert_eq!(ChannelType::from_path("dingtalk"), Some(ChannelType::DingTalk));
        assert_eq!(ChannelType::from_path("wecom"), Some(ChannelType::WeCom));
        assert_eq!(ChannelType::from_path("wechat"), Some(ChannelType::WeCom));
        assert_eq!(ChannelType::from_path("webchat"), Some(ChannelType::WebChat));
        assert_eq!(ChannelType::from_path("web"), Some(ChannelType::WebChat));
        assert_eq!(ChannelType::from_path("unknown"), None);
    }

    #[test]
    fn test_channel_type_from_path_case_insensitive() {
        assert_eq!(ChannelType::from_path("Telegram"), Some(ChannelType::Telegram));
        assert_eq!(ChannelType::from_path("SLACK"), Some(ChannelType::Slack));
    }

    #[test]
    fn test_channel_type_serialization() {
        let json = serde_json::to_string(&ChannelType::Telegram).unwrap();
        assert_eq!(json, "\"telegram\"");
        let parsed: ChannelType = serde_json::from_str("\"slack\"").unwrap();
        assert_eq!(parsed, ChannelType::Slack);
    }

    #[test]
    fn test_parse_telegram() {
        let payload = serde_json::json!({
            "message": {
                "message_id": 123,
                "chat": {"id": 456},
                "from": {"id": 789, "first_name": "Alice"},
                "text": "Hello bot",
                "date": 1700000000
            }
        });
        let msg = WebhookHandler::parse(&ChannelType::Telegram, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.channel, ChannelType::Telegram);
        assert_eq!(msg.id, "123");
        assert_eq!(msg.chat_id, "456");
        assert_eq!(msg.sender_id, "789");
        assert_eq!(msg.sender_name, Some("Alice".to_string()));
        assert_eq!(msg.content, "Hello bot");
        assert_eq!(msg.timestamp, 1700000000000);
    }

    #[test]
    fn test_parse_slack() {
        let payload = serde_json::json!({
            "event": {
                "client_msg_id": "msg-001",
                "channel": "C123",
                "user": "U456",
                "text": "Hello from Slack",
                "ts": "1700000000.000100"
            }
        });
        let msg = WebhookHandler::parse(&ChannelType::Slack, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.channel, ChannelType::Slack);
        assert_eq!(msg.id, "msg-001");
        assert_eq!(msg.chat_id, "C123");
        assert_eq!(msg.sender_id, "U456");
        assert_eq!(msg.content, "Hello from Slack");
    }

    #[test]
    fn test_parse_discord() {
        let payload = serde_json::json!({
            "id": "msg-001",
            "channel_id": "ch-001",
            "author": {"id": "user-001", "username": "Bob"},
            "content": "Hello from Discord"
        });
        let msg = WebhookHandler::parse(&ChannelType::Discord, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.channel, ChannelType::Discord);
        assert_eq!(msg.content, "Hello from Discord");
        assert_eq!(msg.sender_name, Some("Bob".to_string()));
    }

    #[test]
    fn test_parse_dingtalk() {
        let payload = serde_json::json!({
            "msgId": "msg-001",
            "conversationId": "conv-001",
            "senderStaffId": "staff-001",
            "senderNick": "Charlie",
            "text": {"content": "Hello from DingTalk"},
            "createAt": 1700000000000u64
        });
        let msg = WebhookHandler::parse(&ChannelType::DingTalk, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.channel, ChannelType::DingTalk);
        assert_eq!(msg.content, "Hello from DingTalk");
        assert_eq!(msg.sender_name, Some("Charlie".to_string()));
    }

    #[test]
    fn test_parse_wecom() {
        let payload = serde_json::json!({
            "MsgId": "msg-001",
            "FromUserName": "user-001",
            "Content": "Hello from WeCom",
            "CreateTime": 1700000000u64
        });
        let msg = WebhookHandler::parse(&ChannelType::WeCom, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.channel, ChannelType::WeCom);
        assert_eq!(msg.content, "Hello from WeCom");
        assert_eq!(msg.timestamp, 1700000000000);
    }

    #[test]
    fn test_parse_webchat() {
        let payload = serde_json::json!({
            "id": "msg-001",
            "session_id": "sess-001",
            "user_id": "user-001",
            "user_name": "Dave",
            "content": "Hello from WebChat",
            "timestamp": 1700000000000u64
        });
        let msg = WebhookHandler::parse(&ChannelType::WebChat, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.channel, ChannelType::WebChat);
        assert_eq!(msg.content, "Hello from WebChat");
        assert_eq!(msg.sender_name, Some("Dave".to_string()));
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = WebhookHandler::parse(&ChannelType::Telegram, b"not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid JSON"));
    }

    #[test]
    fn test_parse_telegram_reply() {
        let payload = serde_json::json!({
            "message": {
                "message_id": 124,
                "chat": {"id": 456},
                "from": {"id": 789},
                "text": "Reply",
                "date": 1700000000,
                "reply_to_message": {"message_id": 123}
            }
        });
        let msg = WebhookHandler::parse(&ChannelType::Telegram, payload.to_string().as_bytes()).unwrap();
        assert_eq!(msg.reply_to, Some("123".to_string()));
    }

    #[test]
    fn test_channel_message_serialization() {
        let msg = ChannelMessage {
            id: "1".to_string(),
            channel: ChannelType::Telegram,
            chat_id: "chat-1".to_string(),
            sender_id: "user-1".to_string(),
            sender_name: Some("Test".to_string()),
            content: "Hello".to_string(),
            timestamp: 1000,
            reply_to: None,
            raw: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ChannelMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "1");
        assert_eq!(parsed.channel, ChannelType::Telegram);
        assert_eq!(parsed.content, "Hello");
    }
}
