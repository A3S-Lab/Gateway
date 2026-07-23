//! Request and upstream-attempt identities for managed inference.

use crate::config::InferenceEndpoint;
use http::{HeaderMap, HeaderValue, Response};
use uuid::Uuid;

pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
pub(crate) const ATTEMPT_ID_HEADER: &str = "x-a3s-attempt-id";

/// Stable identity and correlation context for one managed inference request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferenceRequestIdentity {
    request_id: Uuid,
    correlation_id: String,
    route_id: Uuid,
    route_policy_revision: u64,
    endpoint: InferenceEndpoint,
    model_id: Option<Uuid>,
}

impl InferenceRequestIdentity {
    pub(crate) fn new(
        correlation_id: String,
        route_id: Uuid,
        route_policy_revision: u64,
        endpoint: InferenceEndpoint,
    ) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            correlation_id,
            route_id,
            route_policy_revision,
            endpoint,
            model_id: None,
        }
    }

    pub(crate) fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub(crate) fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    pub(crate) fn route_id(&self) -> Uuid {
        self.route_id
    }

    pub(crate) fn route_policy_revision(&self) -> u64 {
        self.route_policy_revision
    }

    pub(crate) fn endpoint(&self) -> InferenceEndpoint {
        self.endpoint
    }

    pub(crate) fn model_id(&self) -> Option<Uuid> {
        self.model_id
    }

    pub(crate) fn set_model_id(&mut self, model_id: Uuid) {
        self.model_id = Some(model_id);
    }

    /// Replace untrusted client correlation headers with the Gateway-owned
    /// request identity before middleware or upstream dispatch.
    pub(crate) fn prepare_request_headers(&self, headers: &mut HeaderMap) {
        insert_uuid_header(headers, REQUEST_ID_HEADER, self.request_id);
        headers.remove(ATTEMPT_ID_HEADER);
    }

    pub(crate) fn attach_response_header<B>(&self, response: &mut Response<B>) {
        insert_uuid_header(response.headers_mut(), REQUEST_ID_HEADER, self.request_id);
    }

    pub(crate) fn begin_attempt(&self, target_id: Uuid) -> InferenceAttemptIdentity {
        InferenceAttemptIdentity {
            request: self.clone(),
            attempt_id: Uuid::new_v4(),
            target_id,
        }
    }
}

/// Stable identity for one concrete upstream dispatch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferenceAttemptIdentity {
    request: InferenceRequestIdentity,
    attempt_id: Uuid,
    target_id: Uuid,
}

impl InferenceAttemptIdentity {
    pub(crate) fn request(&self) -> &InferenceRequestIdentity {
        &self.request
    }

    pub(crate) fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    pub(crate) fn target_id(&self) -> Uuid {
        self.target_id
    }

    pub(crate) fn prepare_upstream_headers(&self, headers: &mut HeaderMap) {
        self.request.prepare_request_headers(headers);
        insert_uuid_header(headers, ATTEMPT_ID_HEADER, self.attempt_id);
    }

    pub(crate) fn attach_response_header<B>(&self, response: &mut Response<B>) {
        self.request.attach_response_header(response);
    }
}

fn insert_uuid_header(headers: &mut HeaderMap, name: &'static str, value: Uuid) {
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> InferenceRequestIdentity {
        InferenceRequestIdentity::new(
            "0123456789abcdef0123456789abcdef".into(),
            Uuid::new_v4(),
            7,
            InferenceEndpoint::ChatCompletions,
        )
    }

    #[test]
    fn gateway_identity_replaces_untrusted_headers_and_reaches_the_response() {
        let request = request();
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, "client-value".parse().unwrap());
        headers.insert(ATTEMPT_ID_HEADER, "client-attempt".parse().unwrap());

        request.prepare_request_headers(&mut headers);
        assert_eq!(headers[REQUEST_ID_HEADER], request.request_id().to_string());
        assert!(!headers.contains_key(ATTEMPT_ID_HEADER));

        let mut response = Response::new(());
        request.attach_response_header(&mut response);
        assert_eq!(
            response.headers()[REQUEST_ID_HEADER],
            request.request_id().to_string()
        );
    }

    #[test]
    fn attempts_are_unique_and_retain_one_request_and_target_identity() {
        let mut request = request();
        let model_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        request.set_model_id(model_id);
        let first = request.begin_attempt(target_id);
        let second = request.begin_attempt(target_id);

        assert_ne!(first.attempt_id(), second.attempt_id());
        assert_eq!(first.request(), &request);
        assert_eq!(first.target_id(), target_id);
        assert_eq!(first.request().model_id(), Some(model_id));

        let mut headers = HeaderMap::new();
        first.prepare_upstream_headers(&mut headers);
        assert_eq!(headers[REQUEST_ID_HEADER], request.request_id().to_string());
        assert_eq!(headers[ATTEMPT_ID_HEADER], first.attempt_id().to_string());
    }

    #[test]
    fn identity_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<InferenceRequestIdentity>();
        assert_send_sync::<InferenceAttemptIdentity>();
    }
}
