// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

public enum RevocationState {

    /**
     * Certificate is not revoked.
     */
    notRevoked,

    /**
     * Certificate is revoked with a soft revocation.
     */
    softRevoked,

    /**
     * Certificate is revoked with a hard revocation.
     */
    hardRevoked
}
