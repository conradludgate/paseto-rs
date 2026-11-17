#![cfg(feature = "claims")]

use paseto_core::validation::Validate;
use paseto_json::{RegisteredClaims, Time, jiff::Timestamp};

#[test]
fn timestamps_round_trip_as_rfc3339_across_the_unix_epoch() {
    for (seconds, text) in [
        (-1, "1969-12-31T23:59:59Z"),
        (0, "1970-01-01T00:00:00Z"),
        (1, "1970-01-01T00:00:01Z"),
    ] {
        let timestamp = Timestamp::from_second(seconds).unwrap();
        let claims = RegisteredClaims {
            exp: Some(timestamp),
            nbf: Some(timestamp),
            iat: Some(timestamp),
            ..Default::default()
        };
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "exp": text, "nbf": text, "iat": text })
        );
        let decoded: RegisteredClaims = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.nbf, claims.nbf);
        assert_eq!(decoded.iat, claims.iat);
    }
}

#[test]
fn leeway_accepts_nearby_timestamps_and_rejects_more_distant_ones() {
    let now = Timestamp::from_second(1000).unwrap();
    let strict = Time::valid_at(now);
    let leeway = Time::valid_at(now).with_leeway(std::time::Duration::from_secs(10));

    for (exp, nbf, accepted) in [(995, 1005, true), (989, 1005, false), (995, 1011, false)] {
        let claims = RegisteredClaims {
            exp: Some(Timestamp::from_second(exp).unwrap()),
            nbf: Some(Timestamp::from_second(nbf).unwrap()),
            ..Default::default()
        };
        assert!(strict.validate(&claims).is_err());
        assert_eq!(leeway.validate(&claims).is_ok(), accepted);
    }
}
