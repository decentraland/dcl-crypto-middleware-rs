// This was built following the https://adr.decentraland.org/adr/ADR-44
use dcl_crypto::{
    authenticator::WithoutTransport, Address, AuthChain, AuthLink, Authenticator, Web3Transport,
};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

const AUTH_CHAIN_HEADER_PREFIX: &str = "x-identity-auth-chain-";
const AUTH_TIMESTAMP_HEADER: &str = "x-identity-timestamp";
const AUTH_METADATA_HEADER: &str = "x-identity-metadata";
const DEFAULT_EXPIRATION: u32 = 1000 * 60;

/// Errors returned by [`verify`]
#[derive(Debug)]
pub enum AuthMiddlewareError {
    /// A provided header doesn't meet the requirements to be a valid AuthLink of the Authchain
    InvalidMessage,
    /// The provided timestamp within headers is not valid. It's empty or not a number
    InvalidTimestamp,
    /// The provided metadata within headers is not valid. It's empty.
    InvalidMetadata,
    /// The request is unauthorized because the signature is not valid
    Unauthotized,
    /// The request's timestamp expired so the request is unauthorized
    Expired,
    /// A legacy-signed request delivered a declared metadata key under another spelling, or under
    /// two spellings at once. Only returned when [`VerificationOptions::accept_legacy_payload`] is
    /// in use.
    NonCanonicalMetadataKey,
}

/// Options that must be provided to [`verify`] function
pub struct VerificationOptions<T> {
    /// Authenticator must be provided by the crate's user
    authenticator: Authenticator<T>,
    /// Optional expiration time. The default is `1000 * 60` ms
    expirtation: Option<u32>,
    /// When set, the pre-6.0.0 folded payload is accepted as a fallback, and a legacy request must
    /// spell these keys exactly as declared. See [`VerificationOptions::accept_legacy_payload`].
    canonical_metadata_keys: Option<Vec<String>>,
}

impl Default for VerificationOptions<WithoutTransport> {
    fn default() -> Self {
        Self {
            authenticator: Authenticator::new(),
            expirtation: None,
            canonical_metadata_keys: None,
        }
    }
}

impl<T> VerificationOptions<T> {
    pub fn with_authenticator(authenticator: Authenticator<T>) -> Self {
        Self {
            authenticator,
            expirtation: None,
            canonical_metadata_keys: None,
        }
    }

    pub fn authenticator<U>(self, authenticator: Authenticator<U>) -> VerificationOptions<U> {
        VerificationOptions {
            authenticator,
            expirtation: self.expirtation,
            canonical_metadata_keys: self.canonical_metadata_keys,
        }
    }

    pub fn expiration(self, exp: u32) -> Self {
        Self {
            authenticator: self.authenticator,
            expirtation: Some(exp),
            canonical_metadata_keys: self.canonical_metadata_keys,
        }
    }

    /// Also accept signatures built with the pre-6.0.0 payload, where the whole joined string was
    /// folded rather than only the method and the path.
    ///
    /// Opt-in, and deliberately so: accepting that format means metadata *values* are no longer
    /// covered by the signature for those requests. Use it only while clients migrate.
    ///
    /// `canonical_keys` are the metadata keys the service authorizes on, in the spelling it reads
    /// them. A legacy request delivering one of them under another spelling -- or under two at once
    /// -- is refused with [`AuthMiddlewareError::NonCanonicalMetadataKey`] rather than having its
    /// metadata rewritten. Pass an empty slice ONLY if no authorization decision in the service
    /// reads metadata at all; there is then nothing whose spelling could change an outcome.
    ///
    /// The current format is always tried first. The fallback runs only when that fails.
    pub fn accept_legacy_payload(self, canonical_keys: &[&str]) -> Self {
        Self {
            authenticator: self.authenticator,
            expirtation: self.expirtation,
            canonical_metadata_keys: Some(
                canonical_keys.iter().map(|key| key.to_string()).collect(),
            ),
        }
    }
}

/// Verify the Authchain headers provided within request to identify a Decentraland user
///
/// The function will extract the authchain from the headers and verify them to get the user who sent the request
///
/// ## Arguments
/// * method: the request's HTTP method
/// * path: the request's path
/// * headers: the request's headers mapped as a `HashMap<String, String>`
/// * options: [`VerificationOptions`]
///
pub async fn verify<T: Web3Transport>(
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    options: VerificationOptions<T>,
) -> Result<Address, AuthMiddlewareError> {
    let headers = normalize_headers(headers);

    let auth_chain = extract_auth_chain(&headers)?;

    let timestamp = if let Some(ts) = headers.get(AUTH_TIMESTAMP_HEADER) {
        ts
    } else {
        return Err(AuthMiddlewareError::InvalidTimestamp);
    };

    let ts_number = verify_ts(timestamp)?;

    let metadata = if let Some(metadata) = headers.get(AUTH_METADATA_HEADER) {
        metadata
    } else {
        return Err(AuthMiddlewareError::InvalidMetadata);
    };

    let exp = options.expirtation.unwrap_or(DEFAULT_EXPIRATION);

    verify_expiration(ts_number, exp)?;

    let payload = create_payload(method, path, timestamp, metadata);

    match verify_sign(&options.authenticator, &auth_chain, &payload).await {
        Ok(address) => Ok(address),
        Err(err) => {
            // The current format is always tried first, so a service that has not opted in behaves
            // exactly as before this fallback existed.
            let Some(canonical_keys) = options.canonical_metadata_keys.as_ref() else {
                return Err(err);
            };

            // Guarded before the second signature check, not after: the guard is free and the check
            // may cost a web3 round-trip for a contract wallet. A request refused either way should
            // not pay for it.
            assert_legacy_metadata_keys(metadata, canonical_keys)?;

            let legacy = create_legacy_payload(method, path, timestamp, metadata);

            verify_sign(&options.authenticator, &auth_chain, &legacy).await
        }
    }
}

fn extract_auth_chain(headers: &HashMap<String, String>) -> Result<AuthChain, AuthMiddlewareError> {
    let mut index = 0;

    let mut auth_links = vec![];
    while let Some(header) = headers.get(&format!("{}{}", AUTH_CHAIN_HEADER_PREFIX, index)) {
        if let Ok(auth_link) = AuthLink::parse(header) {
            auth_links.push(auth_link);
        } else {
            return Err(AuthMiddlewareError::InvalidMessage);
        }

        index += 1;
    }

    Ok(AuthChain::from(auth_links))
}

fn normalize_headers(headers: HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(key, val)| (key.to_ascii_lowercase(), val.clone()))
        .collect::<HashMap<String, String>>()
}

fn verify_ts(ts: &str) -> Result<u128, AuthMiddlewareError> {
    ts.parse::<u128>()
        .map_err(|_| AuthMiddlewareError::InvalidTimestamp)
}

/// Builds the payload an ADR-44 signature covers.
///
/// The method and the path are lowercased; the metadata is joined VERBATIM, exactly as the
/// `x-identity-metadata` header delivers it.
///
/// That last part is the whole point. This used to lowercase the joined string, metadata included,
/// which left the metadata's casing outside the signature: a client could sign
/// `{"signer":"..."}` and deliver `{"Signer":"..."}` under the same valid signature, and a service
/// reading the delivered header would see a different value than the one that was signed. Joining
/// the bytes as delivered is what binds them.
fn create_payload(method: &str, path: &str, timestamp: &str, metadata: &str) -> String {
    [
        method.to_lowercase().as_str(),
        path.to_lowercase().as_str(),
        timestamp,
        metadata,
    ]
    .join(":")
}

/// The pre-6.0.0 payload: the whole joined string folded, metadata included.
///
/// Kept only so [`VerificationOptions::accept_legacy_payload`] can still verify clients that have
/// not migrated. Never used unless a service opts in.
fn create_legacy_payload(method: &str, path: &str, timestamp: &str, metadata: &str) -> String {
    [method, path, timestamp, metadata].join(":").to_lowercase()
}

/// Refuses legacy-signed metadata that delivers a declared key under another spelling.
///
/// The legacy payload folds the metadata, so `{"Signer":...}` and `{"signer":...}` share one valid
/// signature. A service comparing `metadata["signer"]` reads the first as absent. Requiring the
/// declared spelling removes that ambiguity rather than resolving it: nothing is rewritten, the
/// request is refused.
///
/// Only keys are checked. Values sit outside the legacy signature too and no key list can bind
/// them -- that is the cost of accepting the older format, and it is why this is opt-in.
fn assert_legacy_metadata_keys(
    metadata: &str,
    canonical_keys: &[String],
) -> Result<(), AuthMiddlewareError> {
    if canonical_keys.is_empty() {
        return Ok(());
    }

    let parsed: serde_json::Value =
        serde_json::from_str(metadata).map_err(|_| AuthMiddlewareError::InvalidMetadata)?;

    let Some(object) = parsed.as_object() else {
        // A non-object cannot carry the fields a service reads, and the legacy signature binds
        // none of it. Refused rather than waved through.
        return Err(AuthMiddlewareError::InvalidMetadata);
    };

    for declared in canonical_keys {
        let folded = declared.to_lowercase();
        let delivered: Vec<&String> = object
            .keys()
            .filter(|key| key.to_lowercase() == folded)
            .collect();

        match delivered.len() {
            0 => continue,
            1 if delivered[0] == declared => continue,
            // Either spelled differently, or delivered under two spellings at once -- in which case
            // which one a service reads depends on key order rather than on anything signed.
            _ => return Err(AuthMiddlewareError::NonCanonicalMetadataKey),
        }
    }

    Ok(())
}

async fn verify_sign<T: Web3Transport>(
    authenticator: &Authenticator<T>,
    auth_chain: &AuthChain,
    payload: &str,
) -> Result<Address, AuthMiddlewareError> {
    Ok(authenticator
        .verify_signature(auth_chain, payload)
        .await
        .map_err(|_| AuthMiddlewareError::Unauthotized)?
        .to_owned())
}

fn verify_expiration(ts: u128, expiration: u32) -> Result<(), AuthMiddlewareError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("not unix epoch time")
        .as_millis();

    let expected = ts + expiration as u128;

    if expected < now {
        return Err(AuthMiddlewareError::Expired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::test_utils::create_test_identity;

    use super::*;

    #[tokio::test]
    async fn verify_should_return_ok() {
        let identity = create_test_identity();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let chain = identity.sign_payload(format!("get:/:{}:{}", now, "{}"));

        // Should return OK if the headers are not lowercased
        let mapped_headers = HashMap::from([
            (
                "X-Identity-Auth-Chain-0".to_string(),
                serde_json::to_string(chain.get(0).unwrap()).unwrap(),
            ),
            (
                "X-Identity-Auth-Chain-1".to_string(),
                serde_json::to_string(chain.get(1).unwrap()).unwrap(),
            ),
            (
                "X-Identity-Auth-Chain-2".to_string(),
                serde_json::to_string(chain.get(2).unwrap()).unwrap(),
            ),
            ("X-Identity-Timestamp".to_string(), format!("{}", now)),
            ("X-Identity-Metadata".to_string(), "{}".to_string()),
        ]);

        verify(
            "GET",
            "/",
            mapped_headers,
            VerificationOptions {
                authenticator: Authenticator::new(),
                expirtation: None,
                canonical_metadata_keys: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verify_should_return_err() {
        let mapped_headers = HashMap::from([
            (
                "x-identity-auth-chain-0".to_string(),
                r#"{"type": "SIGNER", "payload": "0x7949f9F239D1a0816ce5Eb364A1F588AE9Cc1Bf5","signature": ""}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-1".to_string(),
                r#"{"type":"ECDSA_EPHEMERAL","payload":"Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z","signature":"0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-2".to_string(),
                r#"{"type":"ECDSA_SIGNED_ENTITY","payload":"get:/api/events:1684936391789:{}","signature":"0xc1511b724b986925896fa7f67f1004b1dbca331f32bea806456ea205904a70f723d1ecb9c0f8c52a930fccb2d2eb61ca715120d57b3226d66d8ce5e63567f27c1c"}"#.to_string(),
            ),
            ("x-identity-timestamp".to_string(), "".to_string()),
            ("x-identity-metadata".to_string(), "{}".to_string()),
        ]);

        assert!(matches!(
            verify(
                "GET",
                "/",
                mapped_headers,
                VerificationOptions {
                    authenticator: Authenticator::new(),
                    expirtation: None,
                    canonical_metadata_keys: None,
                },
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::InvalidTimestamp
        ));

        let mapped_headers = HashMap::from([
            (
                "x-identity-auth-chain-0".to_string(),
                r#"{"type": "SIGNER", "payload": "0x7949f9F239D1a0816ce5Eb364A1F588AE9Cc1Bf5","signature": ""}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-1".to_string(),
                r#"{"type":"ECDSA_EPHEMERAL","payload":"Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z","signature":"0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-2".to_string(),
                r#"{"type":"ECDSA_SIGNED_ENTITY","payload":"get:/api/events:1684936391789:{}","signature":"0xc1511b724b986925896fa7f67f1004b1dbca331f32bea806456ea205904a70f723d1ecb9c0f8c52a930fccb2d2eb61ca715120d57b3226d66d8ce5e63567f27c1c"}"#.to_string(),
            ),
            ("x-identity-metadata".to_string(), "{}".to_string()),
        ]);

        assert!(matches!(
            verify(
                "GET",
                "/",
                mapped_headers,
                VerificationOptions {
                    authenticator: Authenticator::new(),
                    expirtation: None,
                    canonical_metadata_keys: None,
                },
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::InvalidTimestamp
        ));

        let mapped_headers = HashMap::from([
            (
                "x-identity-auth-chain-0".to_string(),
                r#"{"type": "SIGNER", "payload": "0x7949f9F239D1a0816ce5Eb364A1F588AE9Cc1Bf5","signature": ""}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-1".to_string(),
                r#"{"type":"ECDSA_EPHEMERAL","payload":"Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z","signature":"0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-2".to_string(),
                r#"{"type":"ECDSA_SIGNED_ENTITY","payload":"get:/api/events:1684936391789:{}","signature":"0xc1511b724b986925896fa7f67f1004b1dbca331f32bea806456ea205904a70f723d1ecb9c0f8c52a930fccb2d2eb61ca715120d57b3226d66d8ce5e63567f27c1c"}"#.to_string(),
            ),
            ("x-identity-timestamp".to_string(), "1684937236359".to_string()),
        ]);

        assert!(matches!(
            verify(
                "GET",
                "/",
                mapped_headers,
                VerificationOptions {
                    authenticator: Authenticator::new(),
                    expirtation: None,
                    canonical_metadata_keys: None,
                },
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::InvalidMetadata
        ));

        let past_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .checked_sub(Duration::from_secs(120))
            .unwrap()
            .as_millis();

        let mapped_headers = HashMap::from([
                (
                    "x-identity-auth-chain-0".to_string(),
                    r#"{"type": "SIGNER", "payload": "0x7949f9F239D1a0816ce5Eb364A1F588AE9Cc1Bf5","signature": ""}"#.to_string(),
                ),
                (
                    "x-identity-auth-chain-1".to_string(),
                    r#"{"type":"ECDSA_EPHEMERAL","payload":"Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z","signature":"0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"}"#.to_string(),
                ),
                (
                    "x-identity-auth-chain-2".to_string(),
                    r#"{"type":"ECDSA_SIGNED_ENTITY","payload":"get:/api/events:1684936391789:{}","signature":"0xc1511b724b986925896fa7f67f1004b1dbca331f32bea806456ea205904a70f723d1ecb9c0f8c52a930fccb2d2eb61ca715120d57b3226d66d8ce5e63567f27c1c"}"#.to_string(),
                ),
                ("x-identity-timestamp".to_string(), format!("{}", past_timestamp)),
                ("x-identity-metadata".to_string(), "{}".to_string()),
            ]);

        assert!(matches!(
            verify(
                "GET",
                "/",
                mapped_headers,
                VerificationOptions {
                    authenticator: Authenticator::new(),
                    expirtation: None,
                    canonical_metadata_keys: None,
                },
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::Expired
        ));

        let identity = create_test_identity();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let chain = identity.sign_payload(format!("get:/api/events:{}:{}", now, "{}"));

        // Should return OK if the headers are not lowercased
        let mapped_headers = HashMap::from([
            (
                "X-Identity-Auth-Chain-0".to_string(),
                serde_json::to_string(chain.get(0).unwrap()).unwrap(),
            ),
            (
                "X-Identity-Auth-Chain-1".to_string(),
                serde_json::to_string(chain.get(1).unwrap()).unwrap(),
            ),
            (
                "X-Identity-Auth-Chain-2".to_string(),
                serde_json::to_string(chain.get(2).unwrap()).unwrap(),
            ),
            ("X-Identity-Timestamp".to_string(), format!("{}", now)),
            ("X-Identity-Metadata".to_string(), "{}".to_string()),
        ]);

        assert!(matches!(
            verify(
                "GET",
                "/",
                mapped_headers,
                VerificationOptions {
                    authenticator: Authenticator::new(),
                    expirtation: None,
                    canonical_metadata_keys: None,
                },
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::Unauthotized
        ));
    }

    #[test]
    fn extract_authchain_should_return_ok() {
        let mapped_headers = HashMap::from([
            (
                "x-identity-auth-chain-0".to_string(),
                r#"{"type": "SIGNER", "payload": "0x7949f9F239D1a0816ce5Eb364A1F588AE9Cc1Bf5","signature": ""}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-1".to_string(),
                r#"{"type":"ECDSA_EPHEMERAL","payload":"Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z","signature":"0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-2".to_string(),
                r#"{"type":"ECDSA_SIGNED_ENTITY","payload":"get:/api/events:1684936391789:{}","signature":"0xc1511b724b986925896fa7f67f1004b1dbca331f32bea806456ea205904a70f723d1ecb9c0f8c52a930fccb2d2eb61ca715120d57b3226d66d8ce5e63567f27c1c"}"#.to_string(),
            ),
            ("x-identity-timestamp".to_string(), "1684937236359".to_string()),
            ("x-identity-metadata".to_string(), "{}".to_string()),
        ]);

        assert!(extract_auth_chain(&mapped_headers).is_ok())
    }

    #[test]
    fn extract_authchain_should_return_err() {
        let mapped_headers = HashMap::from([
            (
                "x-identity-auth-chain-0".to_string(),
                r#"{"type": "SIGNER", "payload": "0x7949f9F239D1a0816ce5Eb364A1F588AE9Cc1Bf5","signature": ""}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-1".to_string(),
                r#"{}"#.to_string(),
            ),
            (
                "x-identity-auth-chain-2".to_string(),
                r#"{"type":"ECDSA_SIGNED_ENTITY","payload":"get:/api/events:1684936391789:{}","signature":"0xc1511b724b986925896fa7f67f1004b1dbca331f32bea806456ea205904a70f723d1ecb9c0f8c52a930fccb2d2eb61ca715120d57b3226d66d8ce5e63567f27c1c"}"#.to_string(),
            ),
            ("x-identity-timestamp".to_string(), "1684937236359".to_string()),
            ("x-identity-metadata".to_string(), "{}".to_string()),
        ]);

        assert!(matches!(
            extract_auth_chain(&mapped_headers).unwrap_err(),
            AuthMiddlewareError::InvalidMessage
        ))
    }

    #[test]
    fn verify_ts_should_return_ok() {
        let ts = "1684869538587";

        assert_eq!(verify_ts(ts).unwrap(), 1684869538587)
    }

    #[test]
    fn verify_ts_should_return_err() {
        let ts = "1684869538d587";

        assert!(matches!(
            verify_ts(ts).unwrap_err(),
            AuthMiddlewareError::InvalidTimestamp
        ));
    }

    #[tokio::test]
    async fn verify_sign_should_return_ok() {
        let identity = create_test_identity();
        let signed_fetch = identity.sign_payload("get:/api/events:1684869538587:{}");

        let address = verify_sign(
            &Authenticator::new(),
            &signed_fetch,
            "get:/api/events:1684869538587:{}",
        )
        .await
        .unwrap();

        assert_eq!(
            address.to_string(),
            "0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5"
        )
    }

    #[tokio::test]
    async fn verify_sign_should_return_err() {
        let identity = create_test_identity();
        let signed_fetch = identity.sign_payload("get:/api/events:1684869538587:{}");

        assert!(matches!(
            verify_sign(
                &Authenticator::new(),
                &signed_fetch,
                "get:/api/events:1684869538687:{}",
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::Unauthotized
        ));
    }

    #[test]
    fn expiration_should_return_ok() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        assert!(verify_expiration(now, DEFAULT_EXPIRATION).is_ok());
    }

    #[test]
    fn expiration_should_return_error() {
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .checked_sub(Duration::from_secs(120))
            .unwrap()
            .as_millis();

        assert!(verify_expiration(past, DEFAULT_EXPIRATION).is_err());
    }

    /// Builds signed-fetch headers from a chain, so a test can choose the payload it signs and the
    /// metadata it delivers independently. That split is the whole subject here.
    fn headers_from(
        chain: &AuthChain,
        timestamp: &str,
        delivered_metadata: &str,
    ) -> HashMap<String, String> {
        let links = serde_json::to_value(chain).unwrap();
        let mut headers = HashMap::new();

        for (index, link) in links.as_array().unwrap().iter().enumerate() {
            headers.insert(
                format!("{}{}", AUTH_CHAIN_HEADER_PREFIX, index),
                serde_json::to_string(link).unwrap(),
            );
        }

        headers.insert(AUTH_TIMESTAMP_HEADER.to_string(), timestamp.to_string());
        headers.insert(
            AUTH_METADATA_HEADER.to_string(),
            delivered_metadata.to_string(),
        );

        headers
    }

    fn now_ms() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string()
    }

    /// Metadata that makes folding lossy. All-lowercase metadata folds to itself, so it verifies
    /// identically under both payloads and would prove nothing.
    const MIXED_CASE_METADATA: &str = r#"{"realmName":"Main","signer":"dcl:explorer"}"#;

    #[tokio::test]
    async fn verify_should_bind_the_metadata_bytes_into_the_signature() {
        let identity = create_test_identity();
        let timestamp = now_ms();
        let payload = create_payload("GET", "/api/events", &timestamp, MIXED_CASE_METADATA);
        let chain = identity.sign_payload(payload);

        // Delivered exactly as signed: verifies.
        let headers = headers_from(&chain, &timestamp, MIXED_CASE_METADATA);
        assert!(verify(
            "GET",
            "/api/events",
            headers,
            VerificationOptions::default()
        )
        .await
        .is_ok());

        // Same signature, one key re-cased after signing. Before the metadata bytes were bound this
        // still verified, because folding collapsed both spellings to one payload.
        let tampered = r#"{"RealmName":"Main","signer":"dcl:explorer"}"#;
        let headers = headers_from(&chain, &timestamp, tampered);
        assert!(matches!(
            verify(
                "GET",
                "/api/events",
                headers,
                VerificationOptions::default()
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::Unauthotized
        ));
    }

    #[tokio::test]
    async fn verify_should_refuse_the_legacy_payload_unless_a_service_opts_in() {
        let identity = create_test_identity();
        let timestamp = now_ms();
        let legacy = create_legacy_payload("GET", "/api/events", &timestamp, MIXED_CASE_METADATA);
        let chain = identity.sign_payload(legacy);
        let headers = headers_from(&chain, &timestamp, MIXED_CASE_METADATA);

        assert!(matches!(
            verify(
                "GET",
                "/api/events",
                headers,
                VerificationOptions::default()
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::Unauthotized
        ));
    }

    #[tokio::test]
    async fn verify_should_accept_the_legacy_payload_when_a_service_opts_in() {
        let identity = create_test_identity();
        let timestamp = now_ms();
        let legacy = create_legacy_payload("GET", "/api/events", &timestamp, MIXED_CASE_METADATA);
        let chain = identity.sign_payload(legacy);
        let headers = headers_from(&chain, &timestamp, MIXED_CASE_METADATA);

        assert!(verify(
            "GET",
            "/api/events",
            headers,
            VerificationOptions::default().accept_legacy_payload(&["signer"])
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn verify_should_refuse_a_legacy_request_that_respells_a_declared_key() {
        let identity = create_test_identity();
        let timestamp = now_ms();
        // Folded, this signs identically to the same object spelling the key `signer`, so only the
        // declared-key guard can refuse it. Read as absent, a service gating on `signer` would see
        // metadata that names a signer as carrying none.
        let delivered = r#"{"realmName":"Main","Signer":"dcl:explorer"}"#;
        let legacy = create_legacy_payload("GET", "/api/events", &timestamp, delivered);
        let chain = identity.sign_payload(legacy);
        let headers = headers_from(&chain, &timestamp, delivered);

        assert!(matches!(
            verify(
                "GET",
                "/api/events",
                headers,
                VerificationOptions::default().accept_legacy_payload(&["signer"])
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::NonCanonicalMetadataKey
        ));
    }

    #[tokio::test]
    async fn verify_should_refuse_a_legacy_request_delivering_two_spellings_at_once() {
        let identity = create_test_identity();
        let timestamp = now_ms();
        // Which one a service reads depends on key order, not on anything the signature pinned.
        let delivered = r#"{"signer":"dcl:explorer","Signer":"decentraland-kernel-scene"}"#;
        let legacy = create_legacy_payload("GET", "/api/events", &timestamp, delivered);
        let chain = identity.sign_payload(legacy);
        let headers = headers_from(&chain, &timestamp, delivered);

        assert!(matches!(
            verify(
                "GET",
                "/api/events",
                headers,
                VerificationOptions::default().accept_legacy_payload(&["signer"])
            )
            .await
            .unwrap_err(),
            AuthMiddlewareError::NonCanonicalMetadataKey
        ));
    }
}
