use dcl_crypto::{Address, AuthChain, Authenticator, Web3Transport};
use std::time::Duration;

#[derive(Debug)]
/// Errors returned by [`authenticate_dcl_user`]
pub enum WSAuthError {
    /// Failed while sending the signature challenge to the client
    FailedToSendChallenge,
    /// Signature provided by the client is invalid
    InvalidSignature,
    /// The time elapsed without signed challenge
    Timeout,
    /// The messaged sent by the client is not a valid authchain
    InvalidMessage,
    /// Error on the connection
    ConnectionError,
}

/// Trait that should be implemented by the type in charge of handling the websocket connection for [`authenticate_dcl_user_with_challenge`]
#[async_trait::async_trait]
pub trait AuthenticatedWebSocket {
    type Error;
    /// Sends the signature challenge to the client
    async fn send_signature_challenge(&self, challenge: &str) -> Result<(), Self::Error>;

    /// Receives the authchain with signed challenge
    async fn receive_signed_challenge(&mut self) -> Result<String, Self::Error>;
}

/// Authenticate a WebSocket Connection using the Decentraland's Authchain on a type that implements [`AuthenticatedWebSocket`]
///
/// The function will send a signature challenge and waits for the client's signed authchain.
///
/// The function could fail:
/// * if the client cannot receive the challenge
/// * if the signature is not valid
/// * if the timeout expires
/// * if the client sends a message that it cannot be turned into a string (json)
/// * if an error occurs on the connection
///
/// ## Arguments
/// * `ws`: type implementing [`AuthenticatedWebSocket`]
/// * `timeout`: Amount of seconds to wait for the client to send the auth chain
///
pub async fn authenticate_dcl_user_with_challenge<Ws: AuthenticatedWebSocket, T: Web3Transport>(
    ws: &mut Ws,
    timeout: u64,
    authenticator: Authenticator<T>,
) -> Result<Address, WSAuthError> {
    let message_to_be_firmed = format!("signature_challenge_{}", fastrand::u32(..));

    ws.send_signature_challenge(&message_to_be_firmed)
        .await
        .map_err(|_| WSAuthError::FailedToSendChallenge)?;

    match tokio::time::timeout(Duration::from_secs(timeout), ws.receive_signed_challenge()).await {
        Ok(Ok(client_response)) => {
            let auth_chain = AuthChain::from_json(&client_response).map_err(|e| {
                log::debug!("Invalid auth_chain: {client_response}: {e:?}");
                WSAuthError::InvalidMessage
            })?;
            authenticator
                .verify_signature(&auth_chain, &message_to_be_firmed)
                .await
                .map(|address| address.to_owned())
                .map_err(|e| {
                    log::debug!("Invalid signature: {e:?}");
                    WSAuthError::InvalidSignature
                })
        }
        Ok(Err(_)) => Err(WSAuthError::ConnectionError),
        Err(_) => Err(WSAuthError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // Mock for simulating a connection
    #[async_trait::async_trait]
    impl AuthenticatedWebSocket for InMemory {
        type Error = String;
        async fn send_signature_challenge(&self, challenge: &str) -> Result<(), Self::Error> {
            self.sender.send(challenge.to_string()).await.unwrap();
            Ok(())
        }

        async fn receive_signed_challenge(&mut self) -> Result<String, Self::Error> {
            match self.receiver.recv().await {
                Some(challenge) => match &self.reply_type {
                    ReplyType::AuthChain => {
                        let identity = create_test_identity();
                        let chain = identity.sign_payload(challenge);
                        Ok(serde_json::to_string(&chain).unwrap())
                    }
                    ReplyType::InvalidMessageError => Ok(String::from("")),
                    ReplyType::TimeoutError => {
                        tokio::time::sleep(Duration::from_secs(2)).await; // 1 second passed to the func
                        Ok(String::from(""))
                    }
                    ReplyType::InvalidSignatureError => {
                        let identity = create_test_identity();
                        let chain = identity.sign_payload("challenge");
                        Ok(serde_json::to_string(&chain).unwrap())
                    }
                },
                None => Err("Error".to_string()),
            }
        }
    }

    #[tokio::test]
    async fn authtentication_with_challenge_should_return_ok() {
        let mut in_memory_connection = InMemory::new(ReplyType::AuthChain);
        let address = authenticate_dcl_user_with_challenge(
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
    async fn authtentication_with_challenge_should_return_err() {
        let mut in_memory_connection = InMemory::new(ReplyType::InvalidMessageError);

        assert!(matches!(
            authenticate_dcl_user_with_challenge(
                &mut in_memory_connection,
                1,
                Authenticator::new()
            )
            .await
            .unwrap_err(),
            WSAuthError::InvalidMessage
        ));

        let mut in_memory_connection = InMemory::new(ReplyType::TimeoutError);

        assert!(matches!(
            authenticate_dcl_user_with_challenge(
                &mut in_memory_connection,
                1,
                Authenticator::new()
            )
            .await
            .unwrap_err(),
            WSAuthError::Timeout
        ));

        let mut in_memory_connection = InMemory::new(ReplyType::InvalidSignatureError);

        assert!(matches!(
            authenticate_dcl_user_with_challenge(
                &mut in_memory_connection,
                1,
                Authenticator::new()
            )
            .await
            .unwrap_err(),
            WSAuthError::InvalidSignature
        ))
    }
}
