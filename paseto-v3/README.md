# paseto-v3

AWS-LC based PASETO V3 implementation.

## Examples

```rust
use paseto_v3::{SignedToken, VerifiedToken};
use paseto_v3::key::{SecretKey, PublicKey, SealingKey};
use paseto_json::{RegisteredClaims, jiff};

// create a new keypair
let secret_key = SecretKey::random().unwrap();
let public_key = secret_key.unsealing_key();

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
// parse the token
let signed_token: SignedToken<RegisteredClaims> = token.parse().unwrap();

// parse the key
let public_key: PublicKey = key.parse().unwrap();

// verify the token
let verified_token = signed_token.verify(&public_key).unwrap();

// verify the claims
verified_token.claims.validate_time().unwrap();
```
