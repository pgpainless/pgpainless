// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class CertificationType(
        val signatureType: SignatureType
) {
    /**
     * The issuer of this certification does not make any particular assertion as to how well the certifier has
     * checked that the owner of the key is in fact the person described by the User ID.
     */
    GENERIC(SignatureType.GENERIC_CERTIFICATION),

    /**
     * The issuer of this certification has not done any verification of the claim that the owner of this key is
     * the User ID specified.
     */
    NONE(SignatureType.NO_CERTIFICATION),

    /**
     * The issuer of this certification has done some casual verification of the claim of identity.
     */
    CASUAL(SignatureType.CASUAL_CERTIFICATION),

    /**
     * The issuer of this certification has done some casual verification of the claim of identity.
     */
    POSITIVE(SignatureType.POSITIVE_CERTIFICATION),
    ;

    fun asSignatureType() = signatureType
}