// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation

import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.policy.Policy

/**
 * Interface for a class that negotiates [HashAlgorithms][HashAlgorithm].
 *
 * You can provide your own implementation using custom logic by implementing the
 * [negotiateHashAlgorithm(Set)] method.
 */
interface HashAlgorithmNegotiator {

    /**
     * Pick one [HashAlgorithm] from the ordered set of acceptable algorithms.
     *
     * @param orderedPrefs hash algorithm preferences
     * @return picked algorithms
     */
    fun negotiateHashAlgorithm(orderedPrefs: Set<HashAlgorithm>?): HashAlgorithm

    companion object {

        /**
         * Return an instance that negotiates [HashAlgorithms][HashAlgorithm] used for
         * non-revocation signatures based on the given [Policy].
         *
         * @param policy algorithm policy
         * @return negotiator
         */
        @JvmStatic
        fun negotiateSignatureHashAlgorithm(policy: Policy): HashAlgorithmNegotiator {
            return negotiateByPolicy(policy.dataSignatureHashAlgorithmPolicy)
        }

        /**
         * Return an instance that negotiates [HashAlgorithms][HashAlgorithm] used for revocation
         * signatures based on the given [Policy].
         *
         * @param policy algorithm policy
         * @return negotiator
         */
        @JvmStatic
        fun negotiateRevocationSignatureAlgorithm(policy: Policy): HashAlgorithmNegotiator {
            return negotiateByPolicy(policy.revocationSignatureHashAlgorithmPolicy)
        }

        /**
         * Return an instance that negotiates [HashAlgorithms][HashAlgorithm] based on the given
         * [Policy.HashAlgorithmPolicy].
         *
         * @param hashAlgorithmPolicy algorithm policy for hash algorithms
         * @return negotiator
         */
        @JvmStatic
        fun negotiateByPolicy(
            hashAlgorithmPolicy: Policy.HashAlgorithmPolicy
        ): HashAlgorithmNegotiator {
            return object : HashAlgorithmNegotiator {
                override fun negotiateHashAlgorithm(
                    orderedPrefs: Set<HashAlgorithm>?
                ): HashAlgorithm {
                    return orderedPrefs?.firstOrNull { hashAlgorithmPolicy.isAcceptable(it) }
                        ?: hashAlgorithmPolicy.defaultHashAlgorithm()
                }
            }
        }
    }
}
