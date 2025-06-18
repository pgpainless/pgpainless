// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.bouncycastle.PolicyAdapter;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.NotationRegistry;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PolicyAdapterTest {

    @Test
    public void testNotationRegistryAdaption() {
        NotationRegistry pgpainlessNotationReg = new NotationRegistry();
        pgpainlessNotationReg.addKnownNotation("foo");

        Policy policy = PGPainless.getInstance().getAlgorithmPolicy()
                .copy()
                .withNotationRegistry(pgpainlessNotationReg)
                .build();

        PolicyAdapter adapter = new PolicyAdapter(policy);
        OpenPGPPolicy.OpenPGPNotationRegistry bcNotationReg = adapter.getNotationRegistry();
        assertTrue(bcNotationReg.isNotationKnown("foo"));
        assertFalse(bcNotationReg.isNotationKnown("bar"));
        bcNotationReg.addKnownNotation("bar");

        assertTrue(pgpainlessNotationReg.isKnownNotation("bar"));
    }
}
