// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use crate::params::PUBLIC_PARAMS;
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize}; // G

use crate::{keys::PublicKey, utils::non_zero_scalar};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Ticket {
    pub t_big: RistrettoPoint,
}

pub struct Receipt {
    pub r: Scalar,
    pub tc: Scalar,
}

impl Ticket {
    pub fn create<R>(rng: &mut R, pk: &PublicKey) -> (Ticket, Receipt)
    where
        R: RngCore + CryptoRng,
    {
        // Two random scalars (r, tc)
        // T = tc * Z + r * G
        let receipt = Receipt {
            r: non_zero_scalar(rng),
            tc: non_zero_scalar(rng),
        };

        let ticket = Ticket {
            t_big: (&receipt.r * &PUBLIC_PARAMS.g_big) + (&receipt.tc * &pk.z_big),
        };

        (ticket, receipt)
    }
}
