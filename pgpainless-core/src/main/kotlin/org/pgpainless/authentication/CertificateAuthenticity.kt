// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.authentication

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless

/**
 * A certificate authenticity record, indicating, to what degree the certificate is authenticated.
 *
 * @param userId identity, was changed to [CharSequence] instead of [String] starting with
 *   PGPainless 2.0.
 * @param certificate certificate, was changed to [OpenPGPCertificate] instead of
 *   [PGPPublicKeyRing]. Use [pgpPublicKeyRing] if you need to access a [PGPPublicKeyRing].
 * @param certificationChains map of chains and their trust degrees
 * @param targetAmount targeted trust amount
 */
class CertificateAuthenticity(
    val userId: CharSequence,
    val certificate: OpenPGPCertificate,
    val certificationChains: Map<CertificationChain, Int>,
    val targetAmount: Int
) {

    /** Legacy constructor accepting a [PGPPublicKeyRing]. */
    @Deprecated("Pass in an OpenPGPCertificate instead of a PGPPublicKeyRing.")
    constructor(
        userId: String,
        certificate: PGPPublicKeyRing,
        certificationChains: Map<CertificationChain, Int>,
        targetAmount: Int
    ) : this(
        userId,
        PGPainless.getInstance().toCertificate(certificate),
        certificationChains,
        targetAmount)

    /**
     * Field was introduced to allow backwards compatibility with pre-2.0 API as replacement for
     * [certificate].
     */
    @Deprecated("Use certificate instead.", replaceWith = ReplaceWith("certificate"))
    val pgpPublicKeyRing: PGPPublicKeyRing = certificate.pgpPublicKeyRing

    val totalTrustAmount: Int
        get() = certificationChains.values.sum()

    /**
     * Return the degree of authentication of the binding in percent. 100% means full
     * authentication. Values smaller than 100% mean partial authentication.
     *
     * @return authenticity in percent
     */
    val authenticityPercentage: Int
        get() = targetAmount * 100 / totalTrustAmount

    /**
     * Return true, if the binding is authenticated to a sufficient degree.
     *
     * @return true if total gathered evidence outweighs the target trust amount.
     */
    val authenticated: Boolean
        get() = targetAmount <= totalTrustAmount

    fun isAuthenticated() = authenticated
}

/**
 * A chain of certifications.
 *
 * @param trustAmount actual trust amount of the chain
 * @param chainLinks links of the chain, starting at the trust-root, ending at the target.
 */
class CertificationChain(val trustAmount: Int, val chainLinks: List<ChainLink>) {}

/**
 * A chain link contains a node in the trust chain.
 *
 * @param certificate chain link certificate, was changed from [PGPPublicKeyRing] to
 *   [OpenPGPCertificate] with PGPainless 2.0. Use [pgpPublicKeyRing] if you need to access the
 *   field as [PGPPublicKeyRing].
 */
class ChainLink(val certificate: OpenPGPCertificate) {
    constructor(
        certificate: PGPPublicKeyRing
    ) : this(PGPainless.getInstance().toCertificate(certificate))

    /**
     * Field was introduced to allow backwards compatibility with pre-2.0 API as replacement for
     * [certificate].
     */
    @Deprecated("Use certificate instead.", replaceWith = ReplaceWith("certificate"))
    val pgpPublicKeyRing: PGPPublicKeyRing = certificate.pgpPublicKeyRing
}
