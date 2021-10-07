// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.policy.Policy;

/**
 * Interface for symmetric key algorithm negotiation.
 */
public interface SymmetricKeyAlgorithmNegotiator {

    /**
     * Negotiate a symmetric encryption algorithm.
     *
     * @param policy algorithm policy
     * @param override algorithm override (if not null, return this)
     * @param keyPreferences list of preferences per key
     * @return negotiated algorithm
     */
    SymmetricKeyAlgorithm negotiate(Policy.SymmetricKeyAlgorithmPolicy policy, SymmetricKeyAlgorithm override, List<Set<SymmetricKeyAlgorithm>> keyPreferences);

    static SymmetricKeyAlgorithmNegotiator byPopularity() {
        return new SymmetricKeyAlgorithmNegotiator() {
            @Override
            public SymmetricKeyAlgorithm negotiate(Policy.SymmetricKeyAlgorithmPolicy policy, SymmetricKeyAlgorithm override, List<Set<SymmetricKeyAlgorithm>> preferences) {
                if (override == SymmetricKeyAlgorithm.NULL) {
                    throw new IllegalArgumentException("Algorithm override cannot be NULL (plaintext).");
                }

                if (override != null) {
                    return override;
                }

                // Count score (occurrences) of each algorithm
                Map<SymmetricKeyAlgorithm, Integer> supportWeight = new LinkedHashMap<>();
                for (Set<SymmetricKeyAlgorithm> keyPreferences : preferences) {
                    for (SymmetricKeyAlgorithm preferred : keyPreferences) {
                        if (supportWeight.containsKey(preferred)) {
                            supportWeight.put(preferred, supportWeight.get(preferred) + 1);
                        } else {
                            supportWeight.put(preferred, 1);
                        }
                    }
                }

                // Pivot the score map
                Map<Integer, List<SymmetricKeyAlgorithm>> byScore = new HashMap<>();
                for (SymmetricKeyAlgorithm algorithm : supportWeight.keySet()) {
                    int score = supportWeight.get(algorithm);
                    List<SymmetricKeyAlgorithm> withSameScore = byScore.get(score);
                    if (withSameScore == null) {
                        withSameScore = new ArrayList<>();
                        byScore.put(score, withSameScore);
                    }
                    withSameScore.add(algorithm);
                }

                List<Integer> scores = new ArrayList<>(byScore.keySet());

                // Sort map and iterate from highest to lowest score
                Collections.sort(scores);
                for (int i = scores.size() - 1; i >= 0; i--) {
                    int score = scores.get(i);
                    List<SymmetricKeyAlgorithm> withSameScore = byScore.get(score);
                    // Select best algorithm
                    SymmetricKeyAlgorithm best = policy.selectBest(withSameScore);
                    if (best != null) {
                        return best;
                    }
                }

                // If no algorithm is acceptable, choose fallback
                return policy.getDefaultSymmetricKeyAlgorithm();
            }
        };
    }
}
