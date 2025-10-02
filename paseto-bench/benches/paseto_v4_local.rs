use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use paseto_core::validation::NoValidation;
use paseto_core::version::Local;
use paseto_json::RegisteredClaims;

pub fn criterion_benchmark(c: &mut Criterion) {
    let paseto_v4_key = paseto_v4::LocalKey::random().unwrap();
    let key_bytes = paseto_v4_key.expose_key().as_raw_bytes().to_vec();

    let claims = RegisteredClaims::now(Duration::from_secs(3600))
        .for_audience("https://paseto.io/".to_string())
        .from_issuer("https://github.com/conradludgate/paseto-rs/".to_string())
        .for_subject("conradludgate".to_string());

    let token = paseto_v4::UnencryptedToken::new(claims)
        .encrypt(&paseto_v4_key)
        .unwrap()
        .to_string();

    let mut g = c.benchmark_group("decrypt");

    g.bench_function("paseto_v4", |b| {
        b.iter(|| {
            let token: paseto_v4::EncryptedToken<paseto_json::RegisteredClaims> =
                black_box(&*token).parse().unwrap();

            token
                .decrypt(&paseto_v4_key, &NoValidation::dangerous_no_validation())
                .unwrap()
                .claims
        })
    });

    g.bench_function("paseto_v4_sodium", |b| {
        use paseto_v4_sodium::{EncryptedToken, KeyText, LocalKey};

        let key: LocalKey = KeyText::<Local>::from_raw_bytes(&key_bytes)
            .try_into()
            .unwrap();

        b.iter(|| {
            let token: EncryptedToken<paseto_json::RegisteredClaims> =
                black_box(&*token).parse().unwrap();

            token
                .decrypt(&key, &NoValidation::dangerous_no_validation())
                .unwrap()
                .claims
        })
    });

    g.bench_function("rusty_paseto", |b| {
        use rusty_paseto::prelude::*;

        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&*key_bytes));

        b.iter(|| {
            rusty_paseto::prelude::PasetoParser::<V4, Local>::default()
                .parse(black_box(&*token), &key)
                .unwrap()
        })
    });

    g.bench_function("pasetors", |b| {
        use pasetors::claims::ClaimsValidationRules;
        use pasetors::keys::SymmetricKey;
        use pasetors::token::UntrustedToken;
        use pasetors::{local, version4};

        let key = SymmetricKey::<version4::V4>::from(&key_bytes).unwrap();

        let mut validation = ClaimsValidationRules::new();
        validation.allow_non_expiring();
        validation.disable_valid_at();

        b.iter(|| {
            let token = UntrustedToken::try_from(black_box(&*token)).unwrap();
            black_box(
                local::decrypt(&key, &token, &validation, None, None)
                    .unwrap()
                    .payload_claims()
                    .unwrap(),
            );
        })
    });

    g.finish();

    let mut g = c.benchmark_group("encrypt");

    g.bench_function("paseto_v4", |b| {
        b.iter(|| {
            let token = paseto_v4::UnencryptedToken::new(
                RegisteredClaims::now(Duration::from_secs(3600))
                    .for_audience("https://paseto.io/".to_string())
                    .from_issuer("https://github.com/conradludgate/paseto-rs/".to_string())
                    .for_subject("conradludgate".to_string()),
            );

            token.encrypt(&paseto_v4_key).unwrap().to_string()
        })
    });

    g.bench_function("paseto_v4_sodium", |b| {
        use paseto_v4_sodium::{KeyText, LocalKey, UnencryptedToken};

        let key: LocalKey = KeyText::<Local>::from_raw_bytes(&key_bytes)
            .try_into()
            .unwrap();

        b.iter(|| {
            let token = UnencryptedToken::new(
                RegisteredClaims::now(Duration::from_secs(3600))
                    .for_audience("https://paseto.io/".to_string())
                    .from_issuer("https://github.com/conradludgate/paseto-rs/".to_string())
                    .for_subject("conradludgate".to_string()),
            );

            token.encrypt(&key).unwrap().to_string()
        })
    });

    g.bench_function("rusty_paseto", |b| {
        use rusty_paseto::prelude::*;

        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&*key_bytes));

        b.iter(|| {
            rusty_paseto::prelude::PasetoBuilder::<V4, Local>::default()
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
        use pasetors::keys::SymmetricKey;
        use pasetors::{local, version4};

        let key = SymmetricKey::<version4::V4>::from(&key_bytes).unwrap();

        b.iter(|| {
            let mut claims = Claims::new().unwrap();
            claims.audience("https://paseto.io/").unwrap();
            claims
                .issuer("https://github.com/conradludgate/paseto-rs/")
                .unwrap();
            claims.audience("conradludgate").unwrap();

            local::encrypt(&key, &claims, None, None).unwrap()
        })
    });

    g.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
