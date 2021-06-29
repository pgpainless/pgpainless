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
package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

        assertThrows(IllegalArgumentException.class, () -> SignatureType.isRevocationSignature(-3));
    }
}
