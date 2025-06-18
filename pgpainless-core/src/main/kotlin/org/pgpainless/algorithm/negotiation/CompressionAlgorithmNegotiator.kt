// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation

import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.policy.Policy

fun interface CompressionAlgorithmNegotiator {

    /**
     * Negotiate a suitable [CompressionAlgorithm] by taking into consideration the [Policy], a
     * user-provided [compressionAlgorithmOverride] and the users set of [orderedPreferences].
     *
     * @param policy implementations [Policy]
     * @param compressionAlgorithmOverride user-provided [CompressionAlgorithm] override.
     * @param orderedPreferences preferred compression algorithms taken from the users certificate
     * @return negotiated [CompressionAlgorithm]
     */
    fun negotiate(
        policy: Policy,
        compressionAlgorithmOverride: CompressionAlgorithm?,
        orderedPreferences: Set<CompressionAlgorithm>?
    ): CompressionAlgorithm

    companion object {

        /**
         * Static negotiation of compression algorithms. This implementation discards compression
         * algorithm preferences and instead either returns the non-null algorithm override,
         * otherwise the policies default hash algorithm.
         *
         * @return delegate implementation
         */
        @JvmStatic
        fun staticNegotiation(): CompressionAlgorithmNegotiator =
            CompressionAlgorithmNegotiator { policy, override, _ ->
                override ?: policy.compressionAlgorithmPolicy.defaultCompressionAlgorithm
            }
    }
}
