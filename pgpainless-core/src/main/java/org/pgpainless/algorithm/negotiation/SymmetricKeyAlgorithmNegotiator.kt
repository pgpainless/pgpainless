// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation

import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.policy.Policy
import java.lang.IllegalArgumentException

interface SymmetricKeyAlgorithmNegotiator {

    /**
     * Negotiate a symmetric encryption algorithm.
     * If the override is non-null, it will be returned instead of performing an actual negotiation.
     * Otherwise, the list of ordered sets containing the preferences of different recipient keys will be
     * used to determine a suitable symmetric encryption algorithm.
     *
     * @param policy algorithm policy
     * @param override algorithm override (if not null, return this)
     * @param keyPreferences list of preferences per key
     * @return negotiated algorithm
     */
    fun negotiate(policy: Policy.SymmetricKeyAlgorithmPolicy,
                  override: SymmetricKeyAlgorithm?,
                  keyPreferences: List<Set<SymmetricKeyAlgorithm>>): SymmetricKeyAlgorithm

    companion object {
        @JvmStatic
        fun byPopularity(): SymmetricKeyAlgorithmNegotiator {
            return object: SymmetricKeyAlgorithmNegotiator {
                override fun negotiate(
                        policy: Policy.SymmetricKeyAlgorithmPolicy,
                        override: SymmetricKeyAlgorithm?,
                        keyPreferences: List<Set<SymmetricKeyAlgorithm>>):
                        SymmetricKeyAlgorithm {
                    if (override == SymmetricKeyAlgorithm.NULL) {
                        throw IllegalArgumentException("Algorithm override cannot be NULL (plaintext).")
                    }

                    if (override != null) {
                        return override
                    }

                    // algorithm to #occurrences
                    val supportWeight = buildMap {
                        keyPreferences.forEach { keyPreference ->
                            keyPreference.forEach { pref ->
                                put(pref, getOrDefault(pref, 0) as Int + 1)
                            }
                        }
                    }

                    // Pivot map and sort by popularity ascending
                    // score to list(algo)
                    val byScore = supportWeight.toList()
                            .map { e -> e.second to e.first }
                            .groupBy { e -> e.first }
                            .map { e -> e.key to e.value.map { it.second }.toList() }
                            .associate { e -> e }
                            .toSortedMap()

                    // iterate in reverse over algorithms
                    for (e in byScore.entries.reversed()) {
                        val best = policy.selectBest(e.value)
                        if (best != null) {
                            return best
                        }
                    }

                    return policy.defaultSymmetricKeyAlgorithm
                }

            }
        }
    }
}