// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use crate::{keys::SecretKey, token::Token};

pub fn redeem_token(token: &Token, sk: &SecretKey) -> Result<bool, ()> {
    let false_scalar = &sk.x + (&token.t * &sk.z);
    let true_scalar = &false_scalar + &sk.y;
    let false_point = &false_scalar * &token.p_big;
    let true_point = &true_scalar * &token.p_big;

    let is_true = &true_point == &token.q_big;
    let is_false = &false_point == &token.q_big;

    if !(is_true ^ is_false) {
        return Err(());
    }

    Ok(is_true)
}
