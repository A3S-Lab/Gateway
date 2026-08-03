use super::*;
use crate::config::{
    InferenceGrantConfig, InferenceLimitsConfig, InferenceModelConfig, InferenceTargetConfig,
};
use argon2::password_hash::{PasswordHasher, SaltString};
use http::header::CONTENT_TYPE;
use http::StatusCode;
use std::collections::HashMap;

const PREFIX: &str = "a3s_inf_abc12345";

fn key(character: char) -> String {
    format!("{PREFIX}{}", character.to_string().repeat(64))
}

fn verifier(secret: &str) -> String {
    let salt = SaltString::encode_b64(b"a3s-gateway-test").unwrap();
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn policy(secret: &str) -> (InferenceConfig, Uuid, Uuid) {
    let credential_id = Uuid::new_v4();
    let environment_id = Uuid::new_v4();
    let route_id = Uuid::new_v4();
    let credential = InferenceCredentialConfig {
        credential_id,
        environment_id,
        audience: "cloud-inference".into(),
        prefix: PREFIX.into(),
        verifier_hash: verifier(secret),
        generation: 4,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        revoked: false,
    };
    let grant = InferenceGrantConfig {
        credential_generation: 4,
        models: vec!["beta".into(), "alpha".into()],
        endpoints: vec![
            InferenceEndpoint::Models,
            InferenceEndpoint::ChatCompletions,
        ],
        limits: InferenceLimitsConfig {
            max_concurrent_requests: 2,
            requests_per_minute: 60,
            request_burst: 2,
            tokens_per_minute: 10_000,
        },
    };
    let models = ["alpha", "beta"]
        .into_iter()
        .map(|alias| {
            (
                alias.to_string(),
                InferenceModelConfig {
                    model_id: Uuid::new_v4(),
                    targets: vec![InferenceTargetConfig {
                        target_id: Uuid::new_v4(),
                        service: "model".into(),
                        upstream_model: alias.into(),
                        priority: 0,
                        weight: 1,
                    }],
                },
            )
        })
        .collect();
    let route = InferenceRouteConfig {
        route_id,
        router: "inference".into(),
        environment_id,
        policy_revision: 9,
        models,
        grants: HashMap::from([(credential_id, grant)]),
    };
    (
        InferenceConfig {
            expires_at: Utc::now() + chrono::Duration::hours(1),
            credentials: HashMap::from([(credential_id, credential)]),
            routes: HashMap::from([(route_id, route)]),
        },
        credential_id,
        route_id,
    )
}

fn bearer(secret: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {secret}").parse().unwrap());
    headers
}

#[tokio::test]
async fn authenticates_and_enforces_endpoint_and_model_grants() {
    let secret = key('a');
    let (policy, credential_id, route_id) = policy(&secret);
    let authorizer = InferenceAuthorizer::new(&policy);
    let authenticated = authorizer
        .authenticate(
            "inference",
            OpenAiRequestProfile::ChatCompletions,
            &bearer(&secret),
            Utc::now(),
        )
        .await
        .unwrap();

    assert_eq!(authenticated.credential_id, credential_id);
    assert_eq!(authenticated.route_id, route_id);
    assert!(authorizer
        .select_target_from_priority(authenticated, "alpha", 0, Utc::now(), |_| true)
        .is_ok());
    assert_eq!(
        authorizer
            .allowed_models(authenticated, Utc::now())
            .unwrap(),
        vec!["alpha", "beta"]
    );
    assert_eq!(
        authorizer.select_target_from_priority(authenticated, "gamma", 0, Utc::now(), |_| true),
        Err(InferenceAccessError::Denied)
    );
    assert_eq!(
        authorizer.allowed_models(authenticated, policy.expires_at),
        Err(InferenceAccessError::Unavailable)
    );
    assert_eq!(
        authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::Embeddings,
                &bearer(&secret),
                Utc::now(),
            )
            .await,
        Err(InferenceAccessError::Denied)
    );
}

#[tokio::test]
async fn selects_weighted_targets_then_falls_back_by_priority() {
    let secret = key('a');
    let (mut policy, _, route_id) = policy(&secret);
    policy
        .routes
        .get_mut(&route_id)
        .unwrap()
        .models
        .get_mut("alpha")
        .unwrap()
        .targets = vec![
        InferenceTargetConfig {
            target_id: Uuid::new_v4(),
            service: "primary-a".into(),
            upstream_model: "internal-a".into(),
            priority: 0,
            weight: 1,
        },
        InferenceTargetConfig {
            target_id: Uuid::new_v4(),
            service: "primary-b".into(),
            upstream_model: "internal-b".into(),
            priority: 0,
            weight: 3,
        },
        InferenceTargetConfig {
            target_id: Uuid::new_v4(),
            service: "fallback".into(),
            upstream_model: "internal-fallback".into(),
            priority: 1,
            weight: 1,
        },
    ];
    let authorizer = InferenceAuthorizer::new(&policy);
    let authenticated = authorizer
        .authenticate(
            "inference",
            OpenAiRequestProfile::ChatCompletions,
            &bearer(&secret),
            Utc::now(),
        )
        .await
        .unwrap();

    let selected = (0..4)
        .map(|_| {
            authorizer
                .select_target_from_priority(authenticated, "alpha", 0, Utc::now(), |_| true)
                .unwrap()
                .service
        })
        .collect::<Vec<_>>();
    assert_eq!(
        selected,
        vec!["primary-a", "primary-b", "primary-b", "primary-b"]
    );

    let explicit_fallback = authorizer
        .select_target_from_priority(authenticated, "alpha", 1, Utc::now(), |_| true)
        .unwrap();
    assert_eq!(explicit_fallback.priority, 1);
    assert_eq!(explicit_fallback.service, "fallback");

    let fallback = authorizer
        .select_target_from_priority(authenticated, "alpha", 0, Utc::now(), |service| {
            service == "fallback"
        })
        .unwrap();
    assert_eq!(fallback.service, "fallback");
    assert_eq!(fallback.upstream_model, "internal-fallback");
    assert_eq!(
        authorizer.select_target_from_priority(authenticated, "alpha", 0, Utc::now(), |_| false),
        Err(InferenceAccessError::Unavailable)
    );
}

#[tokio::test]
async fn rejects_zero_weight_runtime_state_without_panicking() {
    let secret = key('a');
    let (mut policy, _, route_id) = policy(&secret);
    policy
        .routes
        .get_mut(&route_id)
        .unwrap()
        .models
        .get_mut("alpha")
        .unwrap()
        .targets[0]
        .weight = 0;
    let authorizer = InferenceAuthorizer::new(&policy);
    let authenticated = authorizer
        .authenticate(
            "inference",
            OpenAiRequestProfile::ChatCompletions,
            &bearer(&secret),
            Utc::now(),
        )
        .await
        .unwrap();

    assert_eq!(
        authorizer.select_target_from_priority(authenticated, "alpha", 0, Utc::now(), |_| true),
        Err(InferenceAccessError::Unavailable)
    );
}

#[tokio::test]
async fn rejects_missing_malformed_unknown_and_wrong_credentials() {
    let secret = key('a');
    let (policy, _, _) = policy(&secret);
    let authorizer = InferenceAuthorizer::new(&policy);
    let mut duplicate = bearer(&secret);
    duplicate.append(AUTHORIZATION, "Bearer duplicate".parse().unwrap());

    for headers in [
        HeaderMap::new(),
        HeaderMap::from_iter([(AUTHORIZATION, "Basic abc".parse().unwrap())]),
        HeaderMap::from_iter([(
            AUTHORIZATION,
            format!("Bearer a3s_inf_unknown{}", "x".repeat(64))
                .parse()
                .unwrap(),
        )]),
        bearer(&key('b')),
        duplicate,
    ] {
        assert_eq!(
            authorizer
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::ChatCompletions,
                    &headers,
                    Utc::now(),
                )
                .await,
            Err(InferenceAccessError::Unauthorized)
        );
    }
    assert_eq!(
        authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::Embeddings,
                &bearer(&key('b')),
                Utc::now(),
            )
            .await,
        Err(InferenceAccessError::Unauthorized)
    );
}

#[tokio::test]
async fn bounds_parallel_argon2_verification() {
    let secret = key('a');
    let (policy, _, _) = policy(&secret);
    let authorizer = InferenceAuthorizer::new(&policy);
    let first = bearer(&key('b'));
    let second = bearer(&key('c'));
    let third = bearer(&key('d'));

    let (first, second, third) = tokio::join!(
        authorizer.authenticate(
            "inference",
            OpenAiRequestProfile::Models,
            &first,
            Utc::now(),
        ),
        authorizer.authenticate(
            "inference",
            OpenAiRequestProfile::Models,
            &second,
            Utc::now(),
        ),
        authorizer.authenticate(
            "inference",
            OpenAiRequestProfile::Models,
            &third,
            Utc::now(),
        ),
    );
    let results = [first, second, third];

    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(InferenceAccessError::Unauthorized))
            .count(),
        MAX_PARALLEL_ARGON2_VERIFICATIONS
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(InferenceAccessError::Unavailable))
            .count(),
        1
    );
}

#[tokio::test]
async fn canceled_callers_keep_argon2_permits_until_work_finishes() {
    let secret = key('a');
    let (policy, _, _) = policy(&secret);
    let mut authorizer = InferenceAuthorizer::new(&policy);
    let (completed, completions) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Barrier::new(
        MAX_PARALLEL_ARGON2_VERIFICATIONS + 1,
    ));
    authorizer.verification_completion_gate = Some(VerificationCompletionGate {
        completed,
        release: release.clone(),
    });
    let authorizer = Arc::new(authorizer);

    let first_authorizer = authorizer.clone();
    let first = tokio::spawn(async move {
        first_authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &bearer(&key('b')),
                Utc::now(),
            )
            .await
    });
    let second_authorizer = authorizer.clone();
    let second = tokio::spawn(async move {
        second_authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &bearer(&key('c')),
                Utc::now(),
            )
            .await
    });

    tokio::task::spawn_blocking(move || {
        for _ in 0..MAX_PARALLEL_ARGON2_VERIFICATIONS {
            completions
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("Argon2 verification did not reach its completion gate");
        }
    })
    .await
    .unwrap();
    assert_eq!(authorizer.verification_permits.available_permits(), 0);
    first.abort();
    second.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(second.await.unwrap_err().is_cancelled());

    assert_eq!(
        authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &bearer(&key('d')),
                Utc::now(),
            )
            .await,
        Err(InferenceAccessError::Unavailable)
    );
    tokio::task::spawn_blocking(move || {
        release.wait();
    })
    .await
    .unwrap();
    let permits = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        authorizer
            .verification_permits
            .clone()
            .acquire_many_owned(MAX_PARALLEL_ARGON2_VERIFICATIONS as u32),
    )
    .await
    .expect("Argon2 permits were not released after verification completed")
    .unwrap();
    drop(permits);
    assert_eq!(
        authorizer.verification_permits.available_permits(),
        MAX_PARALLEL_ARGON2_VERIFICATIONS
    );
}

#[tokio::test]
async fn policy_credential_and_revocation_expiry_fail_closed() {
    let secret = key('a');
    let (mut expired_policy, _, _) = policy(&secret);
    expired_policy.expires_at = Utc::now() - chrono::Duration::seconds(1);
    assert_eq!(
        InferenceAuthorizer::new(&expired_policy)
            .authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &bearer(&secret),
                Utc::now(),
            )
            .await,
        Err(InferenceAccessError::Unavailable)
    );

    for revoked in [false, true] {
        let (mut policy, credential_id, _) = policy(&secret);
        let credential = policy.credentials.get_mut(&credential_id).unwrap();
        credential.revoked = revoked;
        if !revoked {
            credential.expires_at = Utc::now() - chrono::Duration::seconds(1);
        }
        assert_eq!(
            InferenceAuthorizer::new(&policy)
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Models,
                    &bearer(&secret),
                    Utc::now(),
                )
                .await,
            Err(InferenceAccessError::Unauthorized)
        );
    }

    let (mut policy, credential_id, _) = policy(&secret);
    let expires_at = Utc::now() + chrono::Duration::minutes(1);
    policy
        .credentials
        .get_mut(&credential_id)
        .unwrap()
        .expires_at = expires_at;
    let authorizer = InferenceAuthorizer::new(&policy);
    let authenticated = authorizer
        .authenticate(
            "inference",
            OpenAiRequestProfile::Models,
            &bearer(&secret),
            Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(
        authorizer.allowed_models(authenticated, expires_at),
        Err(InferenceAccessError::Unauthorized)
    );
}

#[test]
fn access_errors_are_stable_and_do_not_contain_credentials() {
    let secret = key('a');
    for (error, status) in [
        (InferenceAccessError::Unauthorized, StatusCode::UNAUTHORIZED),
        (InferenceAccessError::Denied, StatusCode::NOT_FOUND),
        (
            InferenceAccessError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            InferenceAccessError::UsageUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            InferenceAccessError::RateLimited {
                retry_after_secs: 17,
            },
            StatusCode::TOO_MANY_REQUESTS,
        ),
        (
            InferenceAccessError::ConcurrencyLimited,
            StatusCode::TOO_MANY_REQUESTS,
        ),
    ] {
        let response = error.into_response();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert!(!response
            .body()
            .windows(secret.len())
            .any(|part| part == secret.as_bytes()));
    }

    let response = InferenceAccessError::RateLimited {
        retry_after_secs: 17,
    }
    .into_response();
    assert_eq!(response.headers()["retry-after"], "17");
    let response = InferenceAccessError::ConcurrencyLimited.into_response();
    assert_eq!(response.headers()["retry-after"], "1");
}

#[test]
fn authorization_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<InferenceAuthorizer>();
    assert_send_sync::<AuthenticatedInference>();
    assert_send_sync::<InferenceDispatchTarget>();
}
