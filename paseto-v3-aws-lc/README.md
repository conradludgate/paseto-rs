# paseto-v3-aws-lc

AWS-LC based PASETO V3 implementation.

## Examples

```rust
use paseto_v3_aws_lc::VerifiedToken;
use paseto_v3_aws_lc::key::{SecretKey, SealingKey};
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
let signed_token = VerifiedToken::new(claims).sign(&secret_key).unwrap();

// serialize the token.
let token = signed_token.to_string();
// "v3.public..."

// serialize the public key.
let key = public_key.to_string();
// "k3.public..."
```

```rust
use paseto_v3_aws_lc::SignedToken;
use paseto_v3_aws_lc::key::PublicKey;
use paseto_json::{RegisteredClaims, Time, MustExpire, FromIssuer, ForSubject, Validate};

// parse the token
let signed_token: SignedToken<RegisteredClaims> = token.parse().unwrap();

// parse the key
let public_key: PublicKey = key.parse().unwrap();

// verify the token signature and validate the claims.
let validation = Time::now()
    .then(MustExpire)
    .then(FromIssuer("https://paseto.conrad.cafe/"))
    .then(ForSubject("conradludgate"));
let verified_token = signed_token.verify(&public_key, &validation).unwrap();
```
