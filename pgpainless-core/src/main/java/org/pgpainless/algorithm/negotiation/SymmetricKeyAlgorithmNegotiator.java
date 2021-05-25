/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.algorithm.negotiation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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

                List<SymmetricKeyAlgorithm> scoreboard = new ArrayList<>(supportWeight.keySet());
                // Sort scoreboard by descending popularity
                Collections.sort(scoreboard, new Comparator<SymmetricKeyAlgorithm>() {
                    @Override
                    public int compare(SymmetricKeyAlgorithm t0, SymmetricKeyAlgorithm t1) {
                        return -supportWeight.get(t0).compareTo(supportWeight.get(t1));
                    }
                });

                for (SymmetricKeyAlgorithm mostWanted : scoreboard) {
                    if (policy.isAcceptable(mostWanted)) {
                        return mostWanted;
                    }
                }

                return policy.getDefaultSymmetricKeyAlgorithm();
            }
        };
    }
}
