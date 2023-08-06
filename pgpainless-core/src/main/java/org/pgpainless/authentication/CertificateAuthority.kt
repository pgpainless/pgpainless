// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.authentication;

import org.pgpainless.key.OpenPgpFingerprint
import java.util.*

/**
 * Interface for a CA that can authenticate trust-worthy certificates.
 * Such a CA might be a fixed list of trustworthy certificates, or a dynamic implementation like the Web-of-Trust.
 *
 * @see <a href="https://github.com/pgpainless/pgpainless-wot">PGPainless-WOT</a>
 * @see <a href="https://sequoia-pgp.gitlab.io/sequoia-wot/">OpenPGP Web of Trust</a>
 */
interface CertificateAuthority {

    /**
     * Determine the authenticity of the binding between the given fingerprint and the userId.
     * In other words, determine, how much evidence can be gathered, that the certificate with the given
     * fingerprint really belongs to the user with the given userId.
     *
     * @param fingerprint fingerprint of the certificate
     * @param userId userId
     * @param email if true, the userId will be treated as an email address and all user-IDs containing
     *             the email address will be matched.
     * @param referenceTime reference time at which the binding shall be evaluated
     * @param targetAmount target trust amount (120 = fully authenticated, 240 = doubly authenticated,
     *                    60 = partially authenticated...)
     * @return information about the authenticity of the binding
     */
    fun authenticateBinding(fingerprint: OpenPgpFingerprint,
                            userId: String,
                            email: Boolean,
                            referenceTime: Date,
                            targetAmount: Int): CertificateAuthenticity;

    /**
     * Lookup certificates, which carry a trustworthy binding to the given userId.
     *
     * @param userId userId
     * @param email if true, the user-ID will be treated as an email address and all user-IDs containing
     *             the email address will be matched.
     * @param referenceTime reference time at which the binding shall be evaluated
     * @param targetAmount target trust amount (120 = fully authenticated, 240 = doubly authenticated,
     *                     60 = partially authenticated...)
     * @return list of identified bindings
     */
    fun lookupByUserId(userId: String,
                       email: Boolean,
                       referenceTime: Date,
                       targetAmount: Int): List<CertificateAuthenticity>

    /**
     * Identify trustworthy bindings for a certificate.
     * The result is a list of authenticatable userIds on the certificate.
     *
     * @param fingerprint fingerprint of the certificate
     * @param referenceTime reference time for trust calculations
     * @param targetAmount target trust amount (120 = fully authenticated, 240 = doubly authenticated,
     *                     60 = partially authenticated...)
     * @return list of identified bindings
     */
    fun identifyByFingerprint(fingerprint: OpenPgpFingerprint,
                              referenceTime: Date,
                              targetAmount: Int): List<CertificateAuthenticity>
}
