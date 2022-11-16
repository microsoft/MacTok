// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use crate::params::PUBLIC_PARAMS;
use crate::{
    keys::{PublicKey, SecretKey},
    prover_server::Proof,
    ticket::Ticket,
    utils::non_zero_scalar,
};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore}; // G, H

pub struct BlindSignature {
    pub u_big: RistrettoPoint,
    pub v_big: RistrettoPoint,
    pub ts: Scalar,
    pub pi: Proof,
}

impl BlindSignature {
    pub fn create<R>(
        rng: &mut R,
        pk: &PublicKey,
        sk: &SecretKey,
        t: &Ticket,
        b: bool,
    ) -> BlindSignature
    where
        R: RngCore + CryptoRng,
    {
        let ts = non_zero_scalar(rng);
        let d = non_zero_scalar(rng);

        let u_big = &d * &PUBLIC_PARAMS.g_big;

        let mut bytes = [0u8; 32];
        bytes[0] = b.into();
        let scalar = Scalar::from_bytes_mod_order(bytes);

        let v_big = (&sk.x_big + (&scalar * &sk.y_big) + (&ts * &pk.z_big) + t.t_big) * &d;

        // generate the proof pi

        let pi = Proof::create(rng, sk, pk, t, &u_big, &v_big, &ts, &scalar, &d);

        let blind_signature = BlindSignature {
            u_big,
            v_big,
            ts,
            pi,
        };
        blind_signature
    }
}
