// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{
    keys::PublicKey, keys::SecretKey, params::PUBLIC_PARAMS, ticket::Ticket,
    utils::non_zero_scalar, utils::one_scalar, utils::ristretto_bytes, utils::scalar_bytes,
    utils::zero_scalar,
};

pub struct Proof {
    pub c_big: RistrettoPoint,
    pub e_zero: Scalar,
    pub e_one: Scalar,
    pub a_zero: Scalar,
    pub a_one: Scalar,
    pub a_d: Scalar,
    pub a_rho: Scalar,
    pub a_w: Scalar,
}

impl Proof {
    pub fn create<R>(
        rng: &mut R,
        sk: &SecretKey,
        pk: &PublicKey,
        t: &Ticket,
        bs_u_big: &RistrettoPoint,
        bs_v_big: &RistrettoPoint,
        bs_ts: &Scalar,
        scalar_b: &Scalar,
        d: &Scalar,
    ) -> Proof
    where
        R: RngCore + CryptoRng,
    {
        // e_one_minus_b, a_one_minus_b <-- ZZ_p
        let simulator_scalars = [Scalar::random(rng); 2];

        // r_mu, r_d, r_rho, r_w <-- ZZ_p
        let commitment_scalars = [Scalar::random(rng); 4];

        // mu <-- ZZ_p*
        let mu = non_zero_scalar(rng);

        // C <-- b * C_y + mu * H; TODO: do not use condition
        let c_big = (scalar_b * &pk.c_big_y) + (&mu * &PUBLIC_PARAMS.h_big);

        // C_b <-- r_mu * H
        let c_big_b = &commitment_scalars[0] * &PUBLIC_PARAMS.h_big;

        // C_one_minus_b <-- a_one_minus_b * H - e_one_minus_b * (C - (1 - b) * C_y)
        let c_minus_c_y = (&one_scalar() - scalar_b) * &pk.c_big_y;
        let point = &c_big - &c_minus_c_y;
        let c_big_one_minus_b =
            (&simulator_scalars[1] * &PUBLIC_PARAMS.h_big) - (&simulator_scalars[0] * point);

        // C_d <-- r_d * U
        let c_big_d = &commitment_scalars[1] * bs_u_big;

        // C_rho <-- r_d * V + r_rho * H
        let r_d_v_big = &commitment_scalars[1] * bs_v_big;
        let c_big_rho = &r_d_v_big + (&commitment_scalars[2] * &PUBLIC_PARAMS.h_big);

        // C_w <-- r_d * V + r_w * G;
        let c_big_w = &r_d_v_big + (&commitment_scalars[3] * &PUBLIC_PARAMS.g_big);

        // e <-- Hash(G, H, C_x, C_y, C, C_zero, C_one_minus_b, C_d, C_rho, C_w) % p;
        let c_big_zero;
        let c_big_one;

        if scalar_b == &zero_scalar() {
            //b is zero
            c_big_zero = c_big_b;
            c_big_one = c_big_one_minus_b;
        } else {
            c_big_one = c_big_b;
            c_big_zero = c_big_one_minus_b;
        }

        let mut hasher = Sha512::new();
        hasher.update(ristretto_bytes(&pk.c_big_x));
        hasher.update(ristretto_bytes(&pk.c_big_y));
        hasher.update(ristretto_bytes(&pk.z_big));
        hasher.update(ristretto_bytes(&bs_u_big));
        hasher.update(ristretto_bytes(&bs_v_big));
        hasher.update(scalar_bytes(&bs_ts));
        hasher.update(ristretto_bytes(&c_big));
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
        let e = Scalar::from_bytes_mod_order_wide(&hash_bytes);

        // e_b <-- e - e_one_minus_b
        let e_b = &e - &simulator_scalars[0];

        // a_b <-- r_mu + e_b * mu
        let a_b = &commitment_scalars[0] + (&e_b * &mu);

        // a_d <-- r_d + e * d' = r_d + e* -1/d
        let a_d = &commitment_scalars[1] - (&e * &(d.invert()));

        // rho <-- -(r_x + b * r_y + mu)
        let rho = -(&sk.r_x + (scalar_b * &sk.r_y) + mu);

        // a_rho <-- r_rho + e * rho
        let a_rho = &commitment_scalars[2] + (&e * &rho);

        // w <-- (x + b * y + ts * z)
        let w = &sk.x + (scalar_b * &sk.y) + bs_ts * &sk.z;

        // a_w <-- r_w + e * w
        let a_w = &commitment_scalars[3] + e * &w;

        let e_zero;
        let e_one;
        let a_zero;
        let a_one;

        if scalar_b == &zero_scalar() {
            e_zero = e_b;
            e_one = simulator_scalars[0];
            a_zero = a_b;
            a_one = simulator_scalars[1];
        } else {
            e_one = e_b;
            e_zero = simulator_scalars[0];
            a_one = a_b;
            a_zero = simulator_scalars[1];
        }

        let pi = Proof {
            c_big,
            e_zero,
            e_one,
            a_zero,
            a_one,
            a_d,
            a_rho,
            a_w,
        };

        pi
    }
}
