# Decentraland Authentication Middleware for Rust

Utils to authenticate a DCL user using the [Authchain](https://docs.decentraland.org/contributor/auth/authchain)

This crate aims to provide all the utilities needed for authenticating an user when creating a new Rust service. 
It can be compared to this [library](https://github.com/decentraland/decentraland-crypto-middleware) for TS

It provides:
- A mechanism for authenticating a WS conneciton. 
- A verification function for signed fetches to be called as a middleware on a HTTP Server.

## Signed payload format

Since `0.3.0` the payload a signature covers is:

```
<lowercased method>:<lowercased path>:<timestamp>:<metadata verbatim>
```

Only the method and the path are lowercased. **The metadata is joined exactly as the
`x-identity-metadata` header delivers it**, so its casing is covered by the signature.

Before `0.3.0` the whole joined string was lowercased, metadata included. That left the metadata's
casing outside the signature: a client could sign `{"signer":"..."}` and deliver `{"Signer":"..."}`
under the same valid signature, and a service reading the delivered header saw a value the signer
never committed to. This matches the same fix in
[`@dcl/crypto-middleware`](https://github.com/decentraland/core-libs) 6.0.0 and
`decentraland-crypto-fetch` 3.0.0.

### Migrating clients that still fold

`0.3.0` is a **breaking change for verification**: a client still building the old payload no longer
verifies once its metadata carries any uppercase. Clients sending `{}` or all-lowercase metadata are
unaffected, because folding those is a no-op.

While clients migrate, a service can accept both:

```rust
VerificationOptions::default().accept_legacy_payload(&["signer", "realmName"])
```

The current format is always tried first; the older one is only attempted if that fails. Declare the
metadata keys the service authorizes on, in the spelling it reads them — a legacy request delivering
one of them under another spelling, or under two at once, is refused rather than having its metadata
rewritten. Pass an empty slice only if no authorization decision in the service reads metadata at
all.

Note what the key list cannot do: the legacy payload folds the metadata, so property *values* sit
outside the signature for those requests and no key list can bind them. That is the cost of
accepting the older format, and the reason this is opt-in and should be time-boxed.
