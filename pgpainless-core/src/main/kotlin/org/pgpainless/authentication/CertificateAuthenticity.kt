// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.authentication

import org.bouncycastle.openpgp.PGPPublicKeyRing

class CertificateAuthenticity(val userId: String,
                              val certificate: PGPPublicKeyRing,
                              val certificationChains: Map<CertificationChain, Int>,
                              val targetAmount: Int) {

    val totalTrustAmount: Int
        get() = certificationChains.values.sum()


    /**
     * Return the degree of authentication of the binding in percent.
     * 100% means full authentication.
     * Values smaller than 100% mean partial authentication.
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
class CertificationChain(
        val trustAmount: Int,
        val chainLinks: List<ChainLink>) {

}

/**
 * A chain link contains a node in the trust chain.
 */
class ChainLink(
        val certificate: PGPPublicKeyRing) {

}