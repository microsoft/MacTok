use crate::keys::*;
use rand_core::OsRng;

#[test]
fn secret_key_test() {
    let mut rng = OsRng;
    let sk1 = SecretKey::create(&mut rng);
    let sk2 = SecretKey::create(&mut rng);
    assert_ne!(sk1, sk2);
}

#[test]
fn secret_key_serialization_test() {
    let mut rng = OsRng;
    let sk1 = SecretKey::create(&mut rng);
    let sk1_str = serde_json::to_string(&sk1).unwrap();

    let sk2: SecretKey = serde_json::from_str(&sk1_str).unwrap();

    assert_eq!(sk1, sk2);
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#[test]
fn client_public_key_serialization_test() {
    let mut rng = OsRng;
    let sk1 = SecretKey::create(&mut rng);
    let cpk1 = PublicKey::create(&sk1);
    let cpk1_str = serde_json::to_string(&cpk1).unwrap();

    let cpk2: PublicKey = serde_json::from_str(&cpk1_str).unwrap();

    assert_eq!(cpk1, cpk2);

    let sk2 = SecretKey::create(&mut rng);
    let cpk3 = PublicKey::create(&sk2);

    assert_ne!(sk1, sk2);
    assert_ne!(cpk1, cpk3);
}
