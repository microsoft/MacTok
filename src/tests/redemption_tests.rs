// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use rand_core::OsRng;

use crate::{
    blind_sig::BlindSignature,
    keys::{PublicKey, SecretKey},
    server::redeem_token,
    ticket::Ticket,
    token::Token,
};

#[test]
pub fn token_redemption_test() {
    let mut rng = OsRng;
    let sk = SecretKey::create(&mut rng);
    let pk = PublicKey::create(&sk);
    let (ticket, receipt) = Ticket::create(&mut rng, &pk);
    let bs = BlindSignature::create(&mut rng, &pk, &sk, &ticket, true);
    let token = Token::create(&mut rng, &pk, &bs, &ticket, &receipt);
    let redemption = redeem_token(&token.unwrap(), &sk);

    assert_eq!(redemption.unwrap(), true);

    let bs = BlindSignature::create(&mut rng, &pk, &sk, &ticket, false);
    let token = Token::create(&mut rng, &pk, &bs, &ticket, &receipt);
    let redemption = redeem_token(&token.unwrap(), &sk);

    assert_eq!(redemption.unwrap(), false);
}

#[test]
pub fn token_redemption_fail_test() {
    let mut rng = OsRng;
    let sk = SecretKey::create(&mut rng);
    let pk = PublicKey::create(&sk);
    let (ticket, receipt) = Ticket::create(&mut rng, &pk);
    let bs = BlindSignature::create(&mut rng, &pk, &sk, &ticket, true);
    let token = Token::create(&mut rng, &pk, &bs, &ticket, &receipt);

    let sk2 = SecretKey::create(&mut rng);
    let redemption = redeem_token(&token.unwrap(), &sk2);

    assert!(redemption.is_err());

    let sk = SecretKey::create(&mut rng);
    let sk2 = SecretKey::create(&mut rng);
    let pk = PublicKey::create(&sk2);
    let (ticket, receipt) = Ticket::create(&mut rng, &pk);
    let bs = BlindSignature::create(&mut rng, &pk, &sk, &ticket, true);
    let token = Token::create(&mut rng, &pk, &bs, &ticket, &receipt);

    assert!(token.is_err());
}
