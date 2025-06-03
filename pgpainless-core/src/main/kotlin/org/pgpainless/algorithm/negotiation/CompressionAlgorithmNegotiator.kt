// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation

import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.policy.Policy

fun interface CompressionAlgorithmNegotiator {
    fun negotiate(
        policy: Policy,
        override: CompressionAlgorithm?,
        orderedPreferences: Set<CompressionAlgorithm>?
    ): CompressionAlgorithm

    companion object {
        @JvmStatic
        fun staticNegotiation(): CompressionAlgorithmNegotiator =
            CompressionAlgorithmNegotiator { policy, override, _ ->
                override ?: policy.compressionAlgorithmPolicy.defaultCompressionAlgorithm
            }
    }
}
