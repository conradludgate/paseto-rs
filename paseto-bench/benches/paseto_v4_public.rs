use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use paseto_core::validation::NoValidation;
use paseto_core::version::Secret;
use paseto_json::RegisteredClaims;

pub fn criterion_benchmark(c: &mut Criterion) {
    let paseto_v4_key = paseto_v4::SecretKey::random().unwrap();

    let priv_key_bytes = paseto_v4_key.expose_key().as_raw_bytes().to_vec();
    let pub_key_bytes = paseto_v4_key
        .public_key()
        .expose_key()
        .as_raw_bytes()
        .to_vec();

    let claims = RegisteredClaims::now(Duration::from_secs(3600))
        .for_audience("https://paseto.io/".to_string())
        .from_issuer("https://github.com/conradludgate/paseto-rs/".to_string())
        .for_subject("conradludgate".to_string());

    let token = paseto_v4::UnsignedToken::new(claims)
        .sign(&paseto_v4_key)
        .unwrap()
        .to_string();

    let mut g = c.benchmark_group("verify");

    g.bench_function("paseto_v4", |b| {
        use paseto_v4::{KeyText, PublicKey, SignedToken};
        let key = PublicKey::try_from(KeyText::from_raw_bytes(&pub_key_bytes)).unwrap();

        b.iter(|| {
            let token: SignedToken<paseto_json::RegisteredClaims> =
                black_box(&*token).parse().unwrap();

            token
                .verify(&key, &NoValidation::dangerous_no_validation())
                .unwrap()
                .claims
        })
    });

    g.bench_function("paseto_v4_sodium", |b| {
        use paseto_v4_sodium::{KeyText, PublicKey, SignedToken};
        let key = PublicKey::try_from(KeyText::from_raw_bytes(&pub_key_bytes)).unwrap();

        b.iter(|| {
            let token: SignedToken<paseto_json::RegisteredClaims> =
                black_box(&*token).parse().unwrap();

            token
                .verify(&key, &NoValidation::dangerous_no_validation())
                .unwrap()
                .claims
        })
    });

    g.bench_function("rusty_paseto", |b| {
        use rusty_paseto::prelude::*;

        let key = Key::from(&*pub_key_bytes);
        let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key);

        b.iter(|| {
            rusty_paseto::prelude::PasetoParser::<V4, Public>::default()
                .parse(black_box(&*token), &key)
                .unwrap()
        })
    });

    g.bench_function("pasetors", |b| {
        use pasetors::claims::ClaimsValidationRules;
        use pasetors::keys::AsymmetricPublicKey;
        use pasetors::token::UntrustedToken;
        use pasetors::{public, version4};

        let key = AsymmetricPublicKey::<version4::V4>::from(&pub_key_bytes).unwrap();

        let mut validation = ClaimsValidationRules::new();
        validation.allow_non_expiring();
        validation.disable_valid_at();

        b.iter(|| {
            let token = UntrustedToken::try_from(black_box(&*token)).unwrap();
            black_box(
                public::verify(&key, &token, &validation, None, None)
                    .unwrap()
                    .payload_claims()
                    .unwrap(),
            );
        })
    });

    g.finish();

    let mut g = c.benchmark_group("sign");

    g.bench_function("paseto_v4", |b| {
        b.iter(|| {
            let token = paseto_v4::UnsignedToken::new(
                RegisteredClaims::now(Duration::from_secs(3600))
                    .for_audience("https://paseto.io/".to_string())
                    .from_issuer("https://github.com/conradludgate/paseto-rs/".to_string())
                    .for_subject("conradludgate".to_string()),
            );

            token.sign(&paseto_v4_key).unwrap().to_string()
        })
    });

    g.bench_function("paseto_v4_sodium", |b| {
        use paseto_v4_sodium::{KeyText, SecretKey, UnsignedToken};

        let key: SecretKey = KeyText::<Secret>::from_raw_bytes(&priv_key_bytes)
            .try_into()
            .unwrap();

        b.iter(|| {
            let token = UnsignedToken::new(
                RegisteredClaims::now(Duration::from_secs(3600))
                    .for_audience("https://paseto.io/".to_string())
                    .from_issuer("https://github.com/conradludgate/paseto-rs/".to_string())
                    .for_subject("conradludgate".to_string()),
            );

            token.sign(&key).unwrap().to_string()
        })
    });

    g.bench_function("rusty_paseto", |b| {
        use rusty_paseto::prelude::*;

        let key = Key::from(&*priv_key_bytes);
        let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key);

        b.iter(|| {
            rusty_paseto::prelude::PasetoBuilder::<V4, Public>::default()
                .set_claim(AudienceClaim::from("https://paseto.io/"))
                .set_claim(IssuerClaim::from(
                    "https://github.com/conradludgate/paseto-rs/",
                ))
                .set_claim(SubjectClaim::from("conradludgate"))
                .build(&key)
                .unwrap()
        })
    });

    g.bench_function("pasetors", |b| {
        use pasetors::claims::Claims;
        use pasetors::keys::AsymmetricSecretKey;
        use pasetors::{public, version4};

        let key = AsymmetricSecretKey::<version4::V4>::from(&priv_key_bytes).unwrap();

        b.iter(|| {
            let mut claims = Claims::new().unwrap();
            claims.audience("https://paseto.io/").unwrap();
            claims
                .issuer("https://github.com/conradludgate/paseto-rs/")
                .unwrap();
            claims.audience("conradludgate").unwrap();

            public::sign(&key, &claims, None, None).unwrap()
        })
    });

    g.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
