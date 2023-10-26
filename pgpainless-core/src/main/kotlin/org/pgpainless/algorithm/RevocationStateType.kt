// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class RevocationStateType {
    /** Certificate is not revoked. */
    notRevoked,

    /** Certificate is revoked with a soft revocation. */
    softRevoked,

    /** Certificate is revoked with a hard revocation. */
    hardRevoked
}
