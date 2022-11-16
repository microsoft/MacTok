// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand_core::{CryptoRng, RngCore};

use crate::{
    blind_sig::BlindSignature,
    keys::PublicKey,
    ticket::{Receipt, Ticket},
    utils::non_zero_scalar,
    verifier_client,
};

pub struct Token {
    pub t: Scalar,
    pub p_big: RistrettoPoint,
    pub q_big: RistrettoPoint,
}

impl Token {
    pub fn create<R>(
        rng: &mut R,
        pk: &PublicKey,
        bs: &BlindSignature,
        ticket: &Ticket,
        receipt: &Receipt,
    ) -> Result<Token, ()>
    where
        R: RngCore + CryptoRng,
    {
        let id = RistrettoPoint::identity();
        if bs.u_big == id {
            return Err(());
        }

        // run verifier_client to verify the proof pi
        if verifier_client::verify_proof(pk, ticket, bs).is_err() {
            return Err(());
        }

        let c = non_zero_scalar(rng);
        let p_big = &bs.u_big * &c;
        let q_big = (&bs.v_big - (&receipt.r * &bs.u_big)) * &c;
        let t = receipt.tc + bs.ts;

        let token = Token { t, p_big, q_big };
        Ok(token)
    }
}
