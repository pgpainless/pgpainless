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
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setCertificationSignatureHashAlgorithmPolicy(null));
    }

    @Test
    public void testSetDataSignatureHashAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setDataSignatureHashAlgorithmPolicy(null));
    }

    @Test
    public void testSetRevocationSignatureHashAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setRevocationSignatureHashAlgorithmPolicy(null));
    }

    @Test
    public void testSetSymmetricKeyEncryptionAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setSymmetricKeyEncryptionAlgorithmPolicy(null));
    }

    @Test
    public void testSetSymmetricKeyDecryptionAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setSymmetricKeyDecryptionAlgorithmPolicy(null));
    }

    @Test
    public void testSetCompressionAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setCompressionAlgorithmPolicy(null));
    }

    @Test
    public void testSetPublicKeyAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setPublicKeyAlgorithmPolicy(null));
    }

    @Test
    public void testNonRegisteredPublicKeyAlgorithm() {
        Policy policy = new Policy();
        Map<PublicKeyAlgorithm, Integer> acceptableAlgorithms = new HashMap<>();
        acceptableAlgorithms.put(PublicKeyAlgorithm.RSA_GENERAL, 2000);
        policy.setPublicKeyAlgorithmPolicy(new Policy.PublicKeyAlgorithmPolicy(acceptableAlgorithms));

        // Policy does not contain ECDSA
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.ECDSA, 256));
    }
}
