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
package org.pgpainless.policy;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

public class PolicySetterTest {

    @Test
    public void testSetSignatureHashAlgorithmPolicy_NullFails() {
        Policy policy = Policy.getInstance();
        assertThrows(NullPointerException.class, () -> policy.setSignatureHashAlgorithmPolicy(null));
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
}
