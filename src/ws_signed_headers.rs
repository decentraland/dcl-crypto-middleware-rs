use crate::signed_fetch::{self, AuthMiddlewareError, VerificationOptions};
use dcl_crypto::{Address, Authenticator, Web3Transport};
use serde_json::Value;
use std::{collections::HashMap, time::Duration};

#[derive(Debug)]
pub enum WSAuthSignedHeadersError {
    /// Error on the connection
    ConnectionError,
    /// The time elapsed without sending the signed headers
    Timeout,
    /// The messaged sent by the client is not a valid authchain
    InvalidMessage,
    /// Error produced by [`signed_fetch::verify`]
    VerifyError(AuthMiddlewareError),
}

/// Trait that should be implemented by the type in charge of handling the websocket connection for [`authenticate_dcl_user_with_signed_headers`]
#[async_trait::async_trait]
pub trait AuthenticatedWSWithSignedHeaders {
    type Error;
    /// Receives the authchain with signed headers
    async fn receive_signed_headers(&mut self) -> Result<String, Self::Error>;
}

pub async fn authenticate_dcl_user_with_signed_headers<
    Ws: AuthenticatedWSWithSignedHeaders,
    T: Web3Transport,
>(
    method: &str,
    path: &str,
    ws: &mut Ws,
    timeout: u64,
    authenticator: Authenticator<T>,
) -> Result<Address, WSAuthSignedHeadersError> {
    match tokio::time::timeout(Duration::from_secs(timeout), ws.receive_signed_headers()).await {
        Ok(Ok(client_response)) => {
            if let Ok(signed_headers) =
                serde_json::from_str::<HashMap<String, Value>>(&client_response)
            {
                let signed_headers = signed_headers
                    .iter()
                    .map(|(key, value)| {
                        let val = match value {
                            Value::Object(_) | Value::Number(_) => value.to_string(),
                            Value::String(s) => s.to_owned(),
                            _ => "".to_string(),
                        };
                        (key.to_owned(), val)
                    })
                    .collect::<HashMap<String, String>>();

                signed_fetch::verify(
                    method,
                    path,
                    signed_headers,
                    VerificationOptions::with_authenticator(authenticator),
                )
                .await
                .map_err(WSAuthSignedHeadersError::VerifyError)
            } else {
                Err(WSAuthSignedHeadersError::InvalidMessage)
            }
        }
        Ok(Err(_)) => Err(WSAuthSignedHeadersError::ConnectionError),
        Err(_) => Err(WSAuthSignedHeadersError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::test_utils::*;

    #[async_trait::async_trait]
    impl AuthenticatedWSWithSignedHeaders for InMemory {
        type Error = String;

        async fn receive_signed_headers(&mut self) -> Result<String, Self::Error> {
            match self.receiver.recv().await {
                Some(challenge) => match &self.reply_type {
                    ReplyType::AuthChain => Ok(challenge),
                    ReplyType::InvalidMessageError => Ok(String::from("")),
                    ReplyType::TimeoutError => {
                        tokio::time::sleep(Duration::from_secs(2)).await; // 1 second passed to the func
                        Ok(String::from(""))
                    }
                    ReplyType::InvalidSignatureError => Ok("".to_string()),
                },
                None => Err("Error".to_string()),
            }
        }
    }

    #[tokio::test]
    async fn authtentication_with_signed_headers_should_return_ok() {
        let identity = create_test_identity();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let chain = identity.sign_payload(format!("get:/:{}:{}", now, "{}"));

        let signed_headers = format!(
            r#"{{"X-Identity-Auth-Chain-0": {},  "X-Identity-Auth-Chain-1": {},  "X-Identity-Auth-Chain-2": {}, "X-Identity-Timestamp": {}, "X-Identity-Metadata": {} }}"#,
            serde_json::to_string(chain.get(0).unwrap()).unwrap(),
            serde_json::to_string(chain.get(1).unwrap()).unwrap(),
            serde_json::to_string(chain.get(2).unwrap()).unwrap(),
            now,
            "{}"
        );

        let mut in_memory_connection = InMemory::new(ReplyType::AuthChain);
        in_memory_connection.send_challenge(&signed_headers).await;

        let address = authenticate_dcl_user_with_signed_headers(
            "get",
            "/",
            &mut in_memory_connection,
            1,
            Authenticator::new(),
        )
        .await
        .unwrap();

        assert_eq!(
            address.to_string(),
            "0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5"
        )
    }

    #[tokio::test]
    async fn authtentication_with_signed_headers_should_return_err() {
        let identity = create_test_identity();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let chain = identity.sign_payload(format!("post:/:{}:{}", now, "{}"));

        let signed_headers = format!(
            r#"{{"X-Identity-Auth-Chain-0": {},  "X-Identity-Auth-Chain-1": {},  "X-Identity-Auth-Chain-2": {}, "X-Identity-Timestamp": {}, "X-Identity-Metadata": {} }}"#,
            serde_json::to_string(chain.get(0).unwrap()).unwrap(),
            serde_json::to_string(chain.get(1).unwrap()).unwrap(),
            serde_json::to_string(chain.get(2).unwrap()).unwrap(),
            now,
            "{}"
        );

        let mut in_memory_connection = InMemory::new(ReplyType::AuthChain);
        in_memory_connection.send_challenge(&signed_headers).await;

        assert!(matches!(
            authenticate_dcl_user_with_signed_headers(
                "get",
                "/",
                &mut in_memory_connection,
                1,
                Authenticator::new(),
            )
            .await
            .unwrap_err(),
            WSAuthSignedHeadersError::VerifyError(AuthMiddlewareError::Unauthotized)
        ));

        let mut in_memory_connection = InMemory::new(ReplyType::AuthChain);
        in_memory_connection.send_challenge("").await;

        assert!(matches!(
            authenticate_dcl_user_with_signed_headers(
                "get",
                "/",
                &mut in_memory_connection,
                1,
                Authenticator::new(),
            )
            .await
            .unwrap_err(),
            WSAuthSignedHeadersError::InvalidMessage
        ))
    }
}
