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
package org.pgpainless;

import static junit.framework.TestCase.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.util.BCUtil;
import org.pgpainless.util.KeyRingSubKeyFix;

public class KeyRingSubKeyFixTest extends AbstractPGPainlessTest {

    @Test
    public void test()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing ring = PGPainless.generateKeyRing().simpleEcKeyRing("hallo@welt.de");
        PGPSecretKeyRing secretKeys = ring.getSecretKeys();
        PGPPublicKeyRing publicKeys = ring.getPublicKeys();

        PGPSecretKeyRing fixed = KeyRingSubKeyFix.repairSubkeyPackets(secretKeys, null, null);

        assertTrue(Arrays.equals(secretKeys.getEncoded(), fixed.getEncoded()));

        PGPPublicKeyRing fixedPub = BCUtil.publicKeyRingFromSecretKeyRing(fixed);

        assertTrue(Arrays.equals(publicKeys.getEncoded(), fixedPub.getEncoded()));
    }
}
