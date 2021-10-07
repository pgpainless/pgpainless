// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPSignature;

public class KeyValidationError extends AssertionError {

    public KeyValidationError(String userId, PGPSignature userIdSig, PGPSignature userIdRevocation) {
        super("User-ID '" + userId + "' is not valid: Sig: " + userIdSig + " Rev: " + userIdRevocation);
    }
}
