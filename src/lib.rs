use dcl_crypto::{Address, AuthChain, Authenticator};
use futures_util::{SinkExt, StreamExt};
use tokio::time::{timeout as timeout_fn, Duration};
use warp::ws::{Message, WebSocket};

pub enum AuthenticationErrors {
    FailedToSendChallenge,
    WrongSignature,
    Timeout,
    NotTextMessage,
    UnexpectedError(Box<dyn std::error::Error + Send + Sync>),
}

/// Authenticate a WebSocket Connection using the Decentraland's Authchain on a [`warp`] server
///
/// The function will send a signature challenge and waits for the client's signed authchain.
///
/// The function could fail:
/// * if the client cannot receive the challenge
/// * if the timeout expires
/// * if the signature is not valid
/// * if the client sends a message that it cannot be turned into a string (json)
/// * if an error occurs on the connection
///
/// ## Arguments
/// * `ws`: [`warp::ws::WebSocket`] given by the [`warp::ws::Ws`] `on_upgrade` closure
/// * `timeout`: Amount of seconds to wait for the client to send the auth chain
///
pub async fn authenticate_dcl_user(
    ws: WebSocket,
    timeout: u64,
) -> Result<(WebSocket, Address), AuthenticationErrors> {
    let authenticator = Authenticator::new();
    let (mut ws_write, mut ws_read) = ws.split();

    let message_to_be_firmed = format!("signature_challenge_{}", fastrand::u32(..));

    if ws_write
        .send(Message::text(&message_to_be_firmed))
        .await
        .is_err()
    {
        return Err(AuthenticationErrors::FailedToSendChallenge);
    }

    match timeout_fn(Duration::from_secs(timeout), ws_read.next()).await {
        Ok(client_response) => {
            let response = client_response.unwrap().unwrap();
            if let Ok(auth_chain) = response.to_str() {
                let auth_chain = AuthChain::from_json(auth_chain).unwrap();
                if let Ok(address) = authenticator
                    .verify_signature(&auth_chain, &message_to_be_firmed)
                    .await
                {
                    let address = address.to_owned();
                    match ws_write.reunite(ws_read) {
                        Ok(ws) => Ok((ws, address)),
                        Err(err) => Err(AuthenticationErrors::UnexpectedError(Box::new(err))),
                    }
                } else if let Err(err) = ws_write.close().await {
                    Err(AuthenticationErrors::UnexpectedError(Box::new(err)))
                } else {
                    Err(AuthenticationErrors::WrongSignature)
                }
            } else {
                Err(AuthenticationErrors::NotTextMessage)
            }
        }
        Err(_) => {
            if let Err(err) = ws_write.close().await {
                Err(AuthenticationErrors::UnexpectedError(Box::new(err)))
            } else {
                Err(AuthenticationErrors::Timeout)
            }
        }
    }
}
