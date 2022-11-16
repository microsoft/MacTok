// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use criterion::{criterion_group, criterion_main, Criterion};
use mactok::{
    blind_sig::BlindSignature, keys::*, server::redeem_token, ticket::Ticket, token::Token,
};
use rand_core::OsRng;

fn benchmark_secret_key(c: &mut Criterion) {
    let mut rng = OsRng;
    c.bench_function("SecretKey create", |b| {
        b.iter(|| SecretKey::create(&mut rng))
    });
}

fn benchmark_secret_key_serialization(c: &mut Criterion) {
    let mut rng = OsRng;
    c.bench_function("SecretKey serialization", |b| {
        b.iter(|| {
            let sk1 = SecretKey::create(&mut rng);
            let sk1_str = serde_json::to_string(&sk1).unwrap();
            let sk2: SecretKey = serde_json::from_str(&sk1_str).unwrap();
        })
    });
}

fn benchmark_public_key_serialization(c: &mut Criterion) {
    let mut rng = OsRng;
    c.bench_function("PublicKey serialization", |b| {
        b.iter(|| {
            let sk1 = SecretKey::create(&mut rng);
            let cpk1 = PublicKey::create(&sk1);
            let cpk1_str = serde_json::to_string(&cpk1).unwrap();
            let cpk2: PublicKey = serde_json::from_str(&cpk1_str).unwrap();
            let sk2 = SecretKey::create(&mut rng);
            let cpk3 = PublicKey::create(&sk2);
        })
    });
}

fn benchmark_redemption(c: &mut Criterion) {
    let mut rng = OsRng;

    c.bench_function("Token redemption", |b| {
        b.iter(|| {
            let sk = SecretKey::create(&mut rng);
            let pk = PublicKey::create(&sk);
            let (ticket, receipt) = Ticket::create(&mut rng, &pk);
            let bs = BlindSignature::create(&mut rng, &pk, &sk, &ticket, true);
            let token = Token::create(&mut rng, &pk, &bs, &ticket, &receipt);
            let redemption = redeem_token(&token.unwrap(), &sk);
        })
    });
}

fn benchmark_redemption_no_keys(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SecretKey::create(&mut rng);
    let pk = PublicKey::create(&sk);
    c.bench_function("Token redemption without KeyGen", |b| {
        b.iter(|| {
            let (ticket, receipt) = Ticket::create(&mut rng, &pk);
            let bs = BlindSignature::create(&mut rng, &pk, &sk, &ticket, true);
            let token = Token::create(&mut rng, &pk, &bs, &ticket, &receipt);
            let redemption = redeem_token(&token.unwrap(), &sk);
        })
    });
}

criterion_group!(
    example_benches,
    benchmark_secret_key,
    benchmark_secret_key_serialization,
    benchmark_public_key_serialization,
    benchmark_redemption,
    benchmark_redemption_no_keys
);
criterion_main!(example_benches);
