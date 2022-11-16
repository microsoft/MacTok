// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek_ng::ristretto::RistrettoBasepointTable;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use lazy_static::lazy_static;
use sha2::Sha512;

lazy_static! {
    pub static ref PUBLIC_PARAMS: PublicParams = PublicParams::create();
}

pub struct PublicParams {
    // The generator G
    pub g_big: RistrettoBasepointTable,

    // The generator H
    pub h_big: RistrettoBasepointTable,
}

impl PublicParams {
    pub fn create() -> PublicParams {
        let pp = PublicParams {
            g_big: RISTRETTO_BASEPOINT_TABLE,
            h_big: RistrettoBasepointTable::create(&RistrettoPoint::hash_from_bytes::<Sha512>(
                &RISTRETTO_BASEPOINT_COMPRESSED.to_bytes(),
            )),
        };
        pp
    }
}
