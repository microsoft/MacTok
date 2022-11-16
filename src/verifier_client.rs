// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use curve25519_dalek_ng::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::{
    blind_sig::BlindSignature, keys::PublicKey, params::PUBLIC_PARAMS, ticket::Ticket,
    utils::ristretto_bytes, utils::scalar_bytes,
};

pub fn verify_proof(pk: &PublicKey, ticket: &Ticket, bs: &BlindSignature) -> Result<bool, ()> {
    // C_0 <-- a_0 * H - e_0 * C
    let c_big_zero = (&bs.pi.a_zero * &PUBLIC_PARAMS.h_big) - (&bs.pi.e_zero * &bs.pi.c_big);

    // C_1 <-- a_1 * H - e_1 * (C - C_y)
    let c_big_one =
        (&bs.pi.a_one * &PUBLIC_PARAMS.h_big) - (&bs.pi.e_one * (&bs.pi.c_big - &pk.c_big_y));

    // e <-- e_0 + e_1
    let e = &bs.pi.e_zero + &bs.pi.e_one;

    // C_d = a_d * U + e * G
    let c_big_d = (&bs.pi.a_d * &bs.u_big) + (&e * &PUBLIC_PARAMS.g_big);

    // C_rho = a_d * V + a_rho * H + e * (C_x + C + ts * Z + T)
    let aux = &pk.c_big_x + &bs.pi.c_big + (&bs.ts * &pk.z_big) + ticket.t_big;
    let a_d_v_big = &bs.pi.a_d * &bs.v_big;
    let c_big_rho = a_d_v_big + (&bs.pi.a_rho * &PUBLIC_PARAMS.h_big) + (&e * &aux);

    // C_w = a_d * V + a_w * G + e * T; TODO: reuse a_d * V
    let c_big_w = a_d_v_big + (&bs.pi.a_w * &PUBLIC_PARAMS.g_big) + (&e * &ticket.t_big);

    // e_verify <-- Hash(G, H, C_x, C_y, C, C_0, C_1, C_d, C_rho, C_w)
    let mut hasher = Sha512::new();
    hasher.update(ristretto_bytes(&pk.c_big_x));
    hasher.update(ristretto_bytes(&pk.c_big_y));
    hasher.update(ristretto_bytes(&pk.z_big));
    hasher.update(ristretto_bytes(&bs.u_big));
    hasher.update(ristretto_bytes(&bs.v_big));
    hasher.update(scalar_bytes(&bs.ts));
    hasher.update(ristretto_bytes(&bs.pi.c_big));
    hasher.update(ristretto_bytes(&c_big_zero));
    hasher.update(ristretto_bytes(&c_big_one));
    hasher.update(ristretto_bytes(&c_big_d));
    hasher.update(ristretto_bytes(&c_big_rho));
    hasher.update(ristretto_bytes(&c_big_w));

    let hash_bytes: [u8; 64] = hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("incorrect size for hash");
    let e_verify = Scalar::from_bytes_mod_order_wide(&hash_bytes);

    if e_verify != e {
        return Err(());
    }

    Ok(true)
}
