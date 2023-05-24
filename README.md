# Decentraland Authentication Middleware for Rust

Utils to authenticate a DCL user using the [Authchain](https://docs.decentraland.org/contributor/auth/authchain)

This crate aims to provide all the utilities needed for authenticating an user when creating a new Rust service. 
It can be compared to this [library](https://github.com/decentraland/decentraland-crypto-middleware) for TS

It provides:
- A mechanism for authenticating a WS conneciton. 
- A verification function for signed fetches to be called as a middleware on a HTTP Server.
