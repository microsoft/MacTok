// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use crate::params::PUBLIC_PARAMS;
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize}; // G

use crate::utils::non_zero_scalar;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub z_big: RistrettoPoint,
    pub c_big_x: RistrettoPoint,
    pub c_big_y: RistrettoPoint,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretKey {
    // 3 scalars
    pub x: Scalar,
    pub y: Scalar,
    // Corresponds to client public key
    pub z: Scalar,
    pub x_big: RistrettoPoint,
    pub y_big: RistrettoPoint,
    // Corresponding to commitments on x and y
    pub r_x: Scalar,
    pub r_y: Scalar,
}

impl SecretKey {
    pub fn create<R>(rng: &mut R) -> SecretKey
    where
        R: RngCore + CryptoRng,
    {
        let x = non_zero_scalar(rng);
        let y = non_zero_scalar(rng);
        let z = non_zero_scalar(rng);
        let r_x = non_zero_scalar(rng);
        let r_y = non_zero_scalar(rng);

        let sk = SecretKey {
            x,
            y,
            z,
            x_big: &PUBLIC_PARAMS.g_big * &x,
            y_big: &PUBLIC_PARAMS.g_big * &y,
            r_x,
            r_y,
        };

        sk
    }
}

impl PublicKey {
    pub fn create(secret_key: &SecretKey) -> PublicKey {
        let spk = PublicKey {
            z_big: &PUBLIC_PARAMS.g_big * &secret_key.z,
            c_big_x: (&secret_key.x * &PUBLIC_PARAMS.g_big)
                + (&secret_key.r_x * &PUBLIC_PARAMS.h_big),
            c_big_y: (&secret_key.y * &PUBLIC_PARAMS.g_big)
                + (&secret_key.r_y * &PUBLIC_PARAMS.h_big),
        };
        spk
    }
}
