// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

pub fn non_zero_scalar<R>(rng: &mut R) -> Scalar
where
    R: RngCore + CryptoRng,
{
    let mut result: Scalar;
    loop {
        result = Scalar::random(rng);
        if result != Scalar::zero() {
            break;
        }
    }
    result
}

pub fn zero_scalar() -> Scalar {
    let bytes = [0u8; 32];
    let scalar = Scalar::from_bytes_mod_order(bytes);
    scalar
}

pub fn one_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    let scalar = Scalar::from_bytes_mod_order(bytes);
    scalar
}

pub fn ristretto_bytes(ristretto_point: &RistrettoPoint) -> [u8; 32] {
    return ristretto_point.compress().to_bytes();
}

pub fn scalar_bytes(ristretto_scalar: &Scalar) -> [u8; 32] {
    return ristretto_scalar.to_bytes();
}
