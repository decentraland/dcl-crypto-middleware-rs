#[cfg(feature = "signed_fetch")]
pub mod signed_fetch;
#[cfg(feature = "ws")]
pub mod ws;
#[cfg(feature = "ws_signed_headers")]
pub mod ws_signed_headers;

#[cfg(test)]
mod test_utils {
    pub enum ReplyType {
        InvalidMessageError,
        InvalidSignatureError,
        TimeoutError,
        AuthChain,
    }

    // Mock for simulating a connection
    pub struct InMemory {
        pub sender: tokio::sync::mpsc::Sender<String>,
        pub receiver: tokio::sync::mpsc::Receiver<String>,
        pub reply_type: ReplyType,
    }

    impl InMemory {
        pub fn new(reply_type: ReplyType) -> Self {
            let chann = tokio::sync::mpsc::channel(1);
            Self {
                sender: chann.0,
                receiver: chann.1,
                reply_type,
            }
        }

        pub async fn send_challenge(&self, auth_chain: &str) {
            self.sender.send(auth_chain.to_string()).await.unwrap();
        }
    }

    pub fn create_test_identity() -> dcl_crypto::Identity {
        dcl_crypto::Identity::from_json(
          r#"{
         "ephemeralIdentity": {
           "address": "0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34",
           "publicKey": "0x0420c548d960b06dac035d1daf826472eded46b8b9d123294f1199c56fa235c89f2515158b1e3be0874bfb15b42d1551db8c276787a654d0b8d7b4d4356e70fe42",
           "privateKey": "0xbc453a92d9baeb3d10294cbc1d48ef6738f718fd31b4eb8085efe7b311299399"
         },
         "expiration": "3021-10-16T22:32:29.626Z",
         "authChain": [
           {
             "type": "SIGNER",
             "payload": "0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5",
             "signature": ""
           },
           {
             "type": "ECDSA_EPHEMERAL",
             "payload": "Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z",
             "signature": "0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"
           }
         ]
        }"#,
      ).unwrap()
    }
}
