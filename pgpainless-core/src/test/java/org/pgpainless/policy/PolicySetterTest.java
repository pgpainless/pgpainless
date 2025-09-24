// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.PublicKeyAlgorithm;

public class PolicySetterTest {

    @Test
    public void testSetCertificationSignatureHashAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withCertificationSignatureHashAlgorithmPolicy(null));
    }

    @Test
    public void testSetDataSignatureHashAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withDataSignatureHashAlgorithmPolicy(null));
    }

    @Test
    public void testSetRevocationSignatureHashAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withRevocationSignatureHashAlgorithmPolicy(null));
    }

    @Test
    public void testSetSymmetricKeyEncryptionAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withSymmetricKeyEncryptionAlgorithmPolicy(null));
    }

    @Test
    public void testSetSymmetricKeyDecryptionAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withSymmetricKeyDecryptionAlgorithmPolicy(null));
    }

    @Test
    public void testSetCompressionAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withCompressionAlgorithmPolicy(null));
    }

    @Test
    public void testSetPublicKeyAlgorithmPolicy_NullFails() {
        Policy policy = new Policy();
        assertThrows(NullPointerException.class, () -> policy.copy().withPublicKeyAlgorithmPolicy(null));
    }

    @Test
    public void testNonRegisteredPublicKeyAlgorithm() {
        Policy policy = new Policy();
        Map<PublicKeyAlgorithm, Integer> acceptableAlgorithms = new HashMap<>();
        acceptableAlgorithms.put(PublicKeyAlgorithm.RSA_GENERAL, 2000);
        policy = policy.copy().withPublicKeyAlgorithmPolicy(new Policy.PublicKeyAlgorithmPolicy(acceptableAlgorithms)).build();

        // Policy does not contain ECDSA
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.ECDSA, 256));
    }
}
