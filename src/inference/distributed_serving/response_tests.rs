use super::contract::{
    ChatResponseChunk, CompletionResponseChunk, DistributedResponseChunk, ProtocolBinding,
};
use super::response::{
    DecodeFrameDecoder, OpenAiAccumulator, OpenAiStreamEncoder, StreamContractError,
    ValidatedDecodeEvent,
};
use crate::config::InferenceEndpoint;
use serde_json::Value;
use uuid::Uuid;

fn binding() -> ProtocolBinding {
    ProtocolBinding {
        execution_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        worker_epoch: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        execution_profile_sha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }
}

#[test]
fn decoder_handles_arbitrary_network_boundaries_and_enforces_terminal_sequence() {
    let input =
        include_bytes!("../../../tests/fixtures/distributed-serving-v1/decode-stream.ndjson");
    let mut decoder = DecodeFrameDecoder::new(binding());
    let mut events = Vec::new();
    for byte in input {
        events.extend(decoder.push(&[*byte]).unwrap());
    }
    decoder.finish().unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], ValidatedDecodeEvent::Chunk(_)));
    assert!(matches!(events[1], ValidatedDecodeEvent::Completed));

    assert_eq!(
        decoder.push(b"{}\n").unwrap_err(),
        StreamContractError::InvalidSequence
    );
}

#[test]
fn decoder_rejects_binding_and_sequence_changes() {
    let mut frame: Value = serde_json::from_str(
        include_str!("../../../tests/fixtures/distributed-serving-v1/decode-stream.ndjson")
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    frame["worker_epoch"] = Value::String(Uuid::from_u128(99).to_string());
    let line = format!("{}\n", serde_json::to_string(&frame).unwrap());
    assert_eq!(
        DecodeFrameDecoder::new(binding())
            .push(line.as_bytes())
            .unwrap_err(),
        StreamContractError::BindingMismatch
    );

    let chunk = include_str!("../../../tests/fixtures/distributed-serving-v1/decode-stream.ndjson")
        .lines()
        .nth(1)
        .unwrap();
    assert_eq!(
        DecodeFrameDecoder::new(binding())
            .push(format!("{chunk}\n").as_bytes())
            .unwrap_err(),
        StreamContractError::InvalidSequence
    );
}

#[test]
fn streaming_translation_emits_openai_sse_and_rejects_endpoint_confusion() {
    let mut encoder = OpenAiStreamEncoder::new(
        InferenceEndpoint::Completions,
        binding().execution_id,
        "external-model".to_string(),
    );
    let bytes = encoder
        .encode_chunk(DistributedResponseChunk::Completions(
            CompletionResponseChunk {
                text: "token".to_string(),
                done: true,
                prompt_tokens: Some(3),
                done_reason: Some("stop".to_string()),
                prompt_eval_duration_ns: None,
                token_id: Some(7),
            },
        ))
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.starts_with("data: {"));
    assert!(text.contains("\"object\":\"text_completion\""));
    assert!(text.contains("\"model\":\"external-model\""));
    assert!(text.ends_with("\n\n"));
    assert_eq!(encoder.encode_done(), b"data: [DONE]\n\n".as_slice());

    assert_eq!(
        encoder
            .encode_chunk(DistributedResponseChunk::ChatCompletions(
                ChatResponseChunk {
                    content: "wrong".to_string(),
                    thinking_content: None,
                    done: false,
                    prompt_tokens: None,
                    done_reason: None,
                    prompt_eval_duration_ns: None,
                    tool_calls: None,
                }
            ))
            .unwrap_err(),
        StreamContractError::EndpointMismatch
    );
}

#[test]
fn buffered_translation_builds_one_openai_chat_response() {
    let mut accumulator = OpenAiAccumulator::new(
        InferenceEndpoint::ChatCompletions,
        binding().execution_id,
        "external-model".to_string(),
    );
    accumulator
        .push(DistributedResponseChunk::ChatCompletions(
            ChatResponseChunk {
                content: "hello ".to_string(),
                thinking_content: Some("reason".to_string()),
                done: false,
                prompt_tokens: None,
                done_reason: None,
                prompt_eval_duration_ns: None,
                tool_calls: None,
            },
        ))
        .unwrap();
    accumulator
        .push(DistributedResponseChunk::ChatCompletions(
            ChatResponseChunk {
                content: "world".to_string(),
                thinking_content: None,
                done: true,
                prompt_tokens: Some(5),
                done_reason: Some("stop".to_string()),
                prompt_eval_duration_ns: None,
                tool_calls: None,
            },
        ))
        .unwrap();
    let response: Value = serde_json::from_slice(&accumulator.finish().unwrap()).unwrap();
    assert_eq!(response["object"], "chat.completion");
    assert_eq!(response["model"], "external-model");
    assert_eq!(response["choices"][0]["message"]["content"], "hello world");
    assert_eq!(
        response["choices"][0]["message"]["reasoning_content"],
        "reason"
    );
    assert_eq!(response["usage"]["prompt_tokens"], 5);
    assert_eq!(response["usage"]["completion_tokens"], 2);
}

#[test]
fn buffered_translation_counts_nonterminal_empty_chunks_like_power() {
    let mut chat = OpenAiAccumulator::new(
        InferenceEndpoint::ChatCompletions,
        binding().execution_id,
        "external-model".to_string(),
    );
    chat.push(DistributedResponseChunk::ChatCompletions(
        ChatResponseChunk {
            content: String::new(),
            thinking_content: None,
            done: false,
            prompt_tokens: None,
            done_reason: None,
            prompt_eval_duration_ns: None,
            tool_calls: None,
        },
    ))
    .unwrap();
    let response: Value = serde_json::from_slice(&chat.finish().unwrap()).unwrap();
    assert_eq!(response["usage"]["completion_tokens"], 1);

    let mut completion = OpenAiAccumulator::new(
        InferenceEndpoint::Completions,
        binding().execution_id,
        "external-model".to_string(),
    );
    completion
        .push(DistributedResponseChunk::Completions(
            CompletionResponseChunk {
                text: String::new(),
                done: false,
                prompt_tokens: None,
                done_reason: None,
                prompt_eval_duration_ns: None,
                token_id: None,
            },
        ))
        .unwrap();
    let response: Value = serde_json::from_slice(&completion.finish().unwrap()).unwrap();
    assert_eq!(response["usage"]["completion_tokens"], 1);
}
