# paseto-v4

RustCrypto based PASETO V4 implementation.

## Examples

```rust
use paseto_v4::{SignedToken, VerifiedToken};
use paseto_v4::key::{SecretKey, PublicKey, SealingKey};
use paseto_json::{RegisteredClaims, jiff};

// create a new keypair
let secret_key = SecretKey::random().unwrap();
let public_key = secret_key.unsealing_key();

// create a set of token claims
let now = jiff::Timestamp::now();
let claims = RegisteredClaims {
    iss: Some("https://paseto.conrad.cafe/".to_string()),
    iat: Some(now),
    nbf: Some(now),
    exp: Some(now + std::time::Duration::from_secs(3600)),
    sub: Some("conradludgate".to_string()),
    ..RegisteredClaims::default()
};

// create and sign a new token
let signed_token = VerifiedToken::new(claims).sign(&secret_key).unwrap();

// serialize the token.
let token = signed_token.to_string();
// "v4.public.eyJpc3MiOiJodHRwczovL3Bhc2V0by5jb25yYWQuY2FmZS8iLCJzdWIiOiJjb25yYWRsdWRnYXRlIiwiYXVkIjpudWxsLCJleHAiOiIyMDI1LTA5LTIwVDEyOjAxOjEzLjcyMjQ3OVoiLCJuYmYiOiIyMDI1LTA5LTIwVDExOjAxOjEzLjcyMjQ3OVoiLCJpYXQiOiIyMDI1LTA5LTIwVDExOjAxOjEzLjcyMjQ3OVoiLCJqdGkiOm51bGx9N7O1CAXQpQ3rpxhq6xFZt32z27VSL8suiek38-5W4LRGr1tDmKcP0_xrlp5-kdE6o7B_K8KU-6Fwmu0hzrkiDQ"

// serialize the public key.
let key = public_key.to_string();
// "k4.public.xRPdFzRvXY-H-6L3S2I3_TmdMKu6XwLKLSR10lZ-yfk"
```

```rust
// parse the token
let signed_token: SignedToken<RegisteredClaims> = token.parse().unwrap();

// parse the key
let public_key: PublicKey = key.parse().unwrap();

// verify the token
let verified_token = signed_token.verify(&public_key).unwrap();

// TODO: verify the claims
let now = jiff::Timestamp::now();
if let Some(exp) = verified_token.message.exp && exp < now {
    panic!("expired");
}
if let Some(nbf) = verified_token.message.nbf && now < nbf {
    panic!("not yet available");
}
```
