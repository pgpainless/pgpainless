// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class SignatureTypeTest {

    @Test
    public void isRevocationSignatureTest() {
        assertTrue(SignatureType.isRevocationSignature(SignatureType.KEY_REVOCATION.getCode()));
        assertTrue(SignatureType.isRevocationSignature(SignatureType.SUBKEY_REVOCATION.getCode()));
        assertTrue(SignatureType.isRevocationSignature(SignatureType.CERTIFICATION_REVOCATION.getCode()));

        assertFalse(SignatureType.isRevocationSignature(SignatureType.BINARY_DOCUMENT.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.CASUAL_CERTIFICATION.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.NO_CERTIFICATION.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.POSITIVE_CERTIFICATION.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.GENERIC_CERTIFICATION.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.CANONICAL_TEXT_DOCUMENT.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.DIRECT_KEY.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.PRIMARYKEY_BINDING.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.SUBKEY_BINDING.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.THIRD_PARTY_CONFIRMATION.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.STANDALONE.getCode()));
        assertFalse(SignatureType.isRevocationSignature(SignatureType.TIMESTAMP.getCode()));

        assertFalse(SignatureType.isRevocationSignature(-3));
    }
}
