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
package org.pgpainless.pgpainless;

import static junit.framework.TestCase.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.Test;
import org.pgpainless.pgpainless.util.BCUtil;

public class ImportExportKeyTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * This test is failing. Not sure if a bug in BC or in my code...
     * @throws PGPException very
     * @throws NoSuchAlgorithmException much
     * @throws NoSuchProviderException some
     * @throws InvalidAlgorithmParameterException annoying
     * @throws IOException exceptions
     */
    @Test
    public void test()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("alice@bla.blub");
        PGPPublicKeyRing publicKeys = BCUtil.publicKeyRingFromSecretKeyRing(secretKeys);

        BcKeyFingerprintCalculator calc = new BcKeyFingerprintCalculator();
        byte[] bytes = publicKeys.getEncoded();
        PGPPublicKeyRing parsed = new PGPPublicKeyRing(bytes, calc);
        assertTrue(Arrays.equals(publicKeys.getEncoded(), parsed.getEncoded()));
    }
}
