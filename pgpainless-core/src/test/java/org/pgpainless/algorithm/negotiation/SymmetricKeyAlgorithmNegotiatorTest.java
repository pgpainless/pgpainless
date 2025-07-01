// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.policy.Policy;

public class SymmetricKeyAlgorithmNegotiatorTest {

    private final SymmetricKeyAlgorithmNegotiator byPopularity = SymmetricKeyAlgorithmNegotiator.byPopularity();
    private final Policy.SymmetricKeyAlgorithmPolicy policy = new Policy.SymmetricKeyAlgorithmPolicy(
            SymmetricKeyAlgorithm.CAMELLIA_256,
            Arrays.asList(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128, SymmetricKeyAlgorithm.CAMELLIA_256));

    @Test
    public void byPopularityReturnsOverrideIfNotNull() {
        assertEquals(SymmetricKeyAlgorithm.AES_192, byPopularity.negotiate(
                policy,
                // override is not null
                SymmetricKeyAlgorithm.AES_192,
                Collections.emptyList()));
    }

    @Test
    public void byPopularityThrowsIAEForUnencryptedOverride() {
        assertThrows(IllegalArgumentException.class, () ->
                byPopularity.negotiate(
                        policy,
                        // Unencrypted is not allowed
                        SymmetricKeyAlgorithm.NULL,
                        Collections.emptyList()));
    }

    @Test
    public void byPopularityChoosesMostPopularAlgorithm() {
        List<Set<SymmetricKeyAlgorithm>> preferences = new ArrayList<>();

        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.AES_128);
            add(SymmetricKeyAlgorithm.AES_192); // <-
            add(SymmetricKeyAlgorithm.AES_256);
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.AES_128);
            add(SymmetricKeyAlgorithm.AES_192); // <-
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.AES_192); // <-
            add(SymmetricKeyAlgorithm.CAMELLIA_256);
        }});

        // AES 192 is most popular
        assertEquals(SymmetricKeyAlgorithm.AES_192, byPopularity.negotiate(policy, null, preferences));
    }

    @Test
    public void byPopularityIgnoresRejectedAlgorithms() {
        List<Set<SymmetricKeyAlgorithm>> preferences = new ArrayList<>();

        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.CAMELLIA_128);
            add(SymmetricKeyAlgorithm.CAMELLIA_192); // <- rejected
            add(SymmetricKeyAlgorithm.AES_256); // <- accepted
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.CAMELLIA_128);
            add(SymmetricKeyAlgorithm.CAMELLIA_192); // <- rejected
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.CAMELLIA_192); // <- rejected
            add(SymmetricKeyAlgorithm.AES_256); // <- accepted
        }});

        // AES 192 is most popular
        assertEquals(SymmetricKeyAlgorithm.AES_256, byPopularity.negotiate(policy, null, preferences));
    }

    @Test
    public void byPopularityChoosesFallbackWhenNoAlgIsAcceptable() {
        List<Set<SymmetricKeyAlgorithm>> preferences = new ArrayList<>();

        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.CAMELLIA_128);
            add(SymmetricKeyAlgorithm.CAMELLIA_192);
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.CAMELLIA_128);
            add(SymmetricKeyAlgorithm.CAMELLIA_192);
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.CAMELLIA_192);
            add(SymmetricKeyAlgorithm.BLOWFISH);
        }});

        // AES 192 is most popular
        assertEquals(SymmetricKeyAlgorithm.CAMELLIA_256, byPopularity.negotiate(policy, null, preferences));
    }

    @Test
    public void byPopularitySelectsBestOnDraw() {
        List<Set<SymmetricKeyAlgorithm>> preferences = new ArrayList<>();

        // Create draw between AES 128 and AES 256
        // The recipients prefer AES 128 first, but we prioritize our policies order
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.AES_128);
            add(SymmetricKeyAlgorithm.AES_192);
            add(SymmetricKeyAlgorithm.AES_256);
        }});
        preferences.add(new LinkedHashSet<SymmetricKeyAlgorithm>(){{
            add(SymmetricKeyAlgorithm.AES_128);
            add(SymmetricKeyAlgorithm.AES_256);
        }});

        assertEquals(SymmetricKeyAlgorithm.AES_256, byPopularity.negotiate(policy, null, preferences));
    }
}
