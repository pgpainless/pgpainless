// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation;

import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.policy.Policy;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CompressionAlgorithmNegotiatorTest {

    @Test
    public void staticNegotiateWithoutOverride() {
        Policy policy = PGPainless.getInstance().getAlgorithmPolicy()
                .copy()
                .withCompressionAlgorithmPolicy(new Policy.CompressionAlgorithmPolicy(
                        CompressionAlgorithm.BZIP2,
                        Arrays.asList(CompressionAlgorithm.BZIP2, CompressionAlgorithm.UNCOMPRESSED)
                ))
                .build();
        CompressionAlgorithmNegotiator negotiator = CompressionAlgorithmNegotiator.staticNegotiation();

        // If the user did not pass an override, return the policy default
        assertEquals(
                CompressionAlgorithm.BZIP2,
                negotiator.negotiate(policy, null, Collections.emptySet()));
    }

    @Test
    public void staticNegotiateWithOverride() {
        Policy policy = PGPainless.getInstance().getAlgorithmPolicy()
                .copy()
                .withCompressionAlgorithmPolicy(new Policy.CompressionAlgorithmPolicy(
                        CompressionAlgorithm.BZIP2,
                        Arrays.asList(CompressionAlgorithm.BZIP2, CompressionAlgorithm.UNCOMPRESSED)
                ))
                .build();
        CompressionAlgorithmNegotiator negotiator = CompressionAlgorithmNegotiator.staticNegotiation();

        // If the user passed an override, return that
        assertEquals(
                CompressionAlgorithm.ZLIB,
                negotiator.negotiate(policy, CompressionAlgorithm.ZLIB, Collections.emptySet()));
    }
}
