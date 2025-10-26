# paseto-v1

RustCrypto based PASETO V1 implementation.

## Examples

```rust
use paseto_v1_aws_lc::UnsignedToken;
use paseto_v1::key::{SecretKey, SealingKey};
use paseto_json::RegisteredClaims;
use std::time::Duration;

// create a new keypair
let secret_key = SecretKey::random().unwrap();
let public_key = secret_key.public_key();

// create a set of token claims
let claims = RegisteredClaims::now(Duration::from_secs(3600))
    .from_issuer("https://paseto.conrad.cafe/".to_string())
    .for_subject("conradludgate".to_string());

// create and sign a new token
let signed_token = UnsignedToken::new(claims).sign(&secret_key).unwrap();

// serialize the token.
let token = signed_token.to_string();
// "v1.public..."

// serialize the public key.
let key = public_key.to_string();
// "k1.public..."
```

```rust
use paseto_v1::SignedToken;
use paseto_v1::key::PublicKey;
use paseto_json::{RegisteredClaims, Time, HasExpiry, FromIssuer, ForSubject, Validate};

// parse the token
let signed_token: SignedToken<RegisteredClaims> = token.parse().unwrap();

// parse the key
let public_key: PublicKey = key.parse().unwrap();

// verify the token signature and validate the claims.
let validation = Time::valid_now()
    .and_then(HasExpiry)
    .and_then(FromIssuer("https://paseto.conrad.cafe/"))
    .and_then(ForSubject("conradludgate"));
let verified_token = signed_token.verify(&public_key, &validation).unwrap();
```
