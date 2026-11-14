// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.authentication

import org.bouncycastle.openpgp.api.OpenPGPCertificate

/**
 * A certificate authenticity record, indicating, to what degree the certificate is authenticated.
 *
 * @param userId identity
 * @param certificate certificate
 * @param certificationChains map of chains and their trust degrees
 * @param targetAmount targeted trust amount
 */
class CertificateAuthenticity(
    val userId: CharSequence,
    val certificate: OpenPGPCertificate,
    val certificationChains: Map<CertificationChain, Int>,
    val targetAmount: Int
) {
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
class CertificationChain(val trustAmount: Int, val chainLinks: List<ChainLink>)

/**
 * A chain link contains a node in the trust chain.
 *
 * @param certificate chain link certificate
 */
class ChainLink(val certificate: OpenPGPCertificate)
