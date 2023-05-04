# dcl-auth-websocket

Authenticate a WebSocket Connection using the Decentraland's Authchain on a [warp](https://github.com/seanmonstar/warp) server

## Example
```rust
use dcl_crypto::{AuthChain, Authenticator};
use futures_util::{SinkExt, StreamExt};
use tokio::time::{timeout, Duration};
use warp::{
    ws::{Message, WebSocket},
    Filter,
};
use dcl_auth_websocket::authenticate_dcl_user

#[tokio::main]
async fn main() {
    let routes = warp::path("ws")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| ws.on_upgrade(|ws| async move {
            let (ws, user_address) = authenticate_dcl_user(ws, 30).await;
            //....
        }));

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
```