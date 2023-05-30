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
}

/// Options that must be provided to [`verify`] function
pub struct VerificationOptions<T> {
    /// Authenticator must be provided by the crate's user
    authenticator: Authenticator<T>,
    /// Optional expiration time. The default is `1000 * 60` ms
    expirtation: Option<u32>,
}

impl Default for VerificationOptions<WithoutTransport> {
    fn default() -> Self {
        Self {
            authenticator: Authenticator::new(),
            expirtation: None,
        }
    }
}

impl<T> VerificationOptions<T> {
    pub fn with_authenticator(authenticator: Authenticator<T>) -> Self {
        Self {
            authenticator,
            expirtation: None,
        }
    }

    pub fn authenticator<U>(self, authenticator: Authenticator<U>) -> VerificationOptions<U> {
        VerificationOptions {
            authenticator,
            expirtation: self.expirtation,
        }
    }

    pub fn expiration(self, exp: u32) -> Self {
        Self {
            authenticator: self.authenticator,
            expirtation: Some(exp),
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

    let payload = create_payload(method, path, timestamp, metadata);

    let exp = options.expirtation.unwrap_or(DEFAULT_EXPIRATION);

    verify_expiration(ts_number, exp)?;

    verify_sign(options.authenticator, auth_chain, &payload).await
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

fn create_payload(method: &str, path: &str, timestamp: &str, metadata: &str) -> String {
    [method, path, timestamp, metadata].join(":").to_lowercase()
}

async fn verify_sign<T: Web3Transport>(
    authenticator: Authenticator<T>,
    auth_chain: AuthChain,
    payload: &str,
) -> Result<Address, AuthMiddlewareError> {
    Ok(authenticator
        .verify_signature(&auth_chain, payload)
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

        let headers_str = serde_json::to_string_pretty(&mapped_headers).unwrap();
        let mapped_headers = serde_json::from_str::<HashMap<String, String>>(&headers_str).unwrap();

        verify(
            "GET",
            "/",
            mapped_headers,
            VerificationOptions {
                authenticator: Authenticator::new(),
                expirtation: None,
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
            Authenticator::new(),
            signed_fetch,
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
                Authenticator::new(),
                signed_fetch,
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
}
