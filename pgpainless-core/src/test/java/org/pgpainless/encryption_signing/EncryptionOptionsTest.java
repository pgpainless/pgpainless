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
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class EncryptionOptionsTest {

    @Test
    public void testOverrideEncryptionAlgorithmFailsForNULL() {
        EncryptionOptions options = new EncryptionOptions();
        assertNull(options.getEncryptionAlgorithmOverride());

        assertThrows(IllegalArgumentException.class, () -> options.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.NULL));

        assertNull(options.getEncryptionAlgorithmOverride());
    }

    @Test
    public void testOverrideEncryptionOptions() {
        EncryptionOptions options = new EncryptionOptions();
        assertNull(options.getEncryptionAlgorithmOverride());
        options.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_128);

        assertEquals(SymmetricKeyAlgorithm.AES_128, options.getEncryptionAlgorithmOverride());
    }
}
