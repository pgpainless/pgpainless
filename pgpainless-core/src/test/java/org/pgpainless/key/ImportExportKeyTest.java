/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;

public class ImportExportKeyTest {

    /**
     * Test the export and import of a key ring with sub keys.
     * @throws IOException in case of a IO error
     */
    @Test
    public void testExportImportPublicKeyRing() throws IOException {
        PGPPublicKeyRing publicKeys = TestKeys.getJulietPublicKeyRing();

        BcKeyFingerprintCalculator calc = new BcKeyFingerprintCalculator();
        byte[] bytes = publicKeys.getEncoded();
        PGPPublicKeyRing parsed = new PGPPublicKeyRing(bytes, calc);
        assertArrayEquals(publicKeys.getEncoded(), parsed.getEncoded());
    }

    @Test
    public void testExportImportSecretKeyRing() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getRomeoSecretKeyRing();
        byte[] bytes = secretKeys.getEncoded();
        PGPSecretKeyRing parsed = new PGPSecretKeyRing(bytes, new BcKeyFingerprintCalculator());
        assertArrayEquals(secretKeys.getEncoded(), parsed.getEncoded());
        assertEquals(secretKeys.getPublicKey().getKeyID(), parsed.getPublicKey().getKeyID());
    }
}
