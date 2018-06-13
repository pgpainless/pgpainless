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
package de.vanitasvitae.crypto.pgpainless;

import static junit.framework.TestCase.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import de.vanitasvitae.crypto.pgpainless.util.BCUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;

public class BCUtilTest extends AbstractPGPainlessTest {

    @Test
    public void test()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        PGPSecretKeyRing sec = PGPainless.generateKeyRing().simpleEcKeyRing("donald@duck.tails");
        PGPPublicKeyRing pub = BCUtil.publicKeyRingFromSecretKeyRing(sec);

        int secSize = 0;
        Iterator<PGPPublicKey> secPubIt = sec.getPublicKeys();
        while (secPubIt.hasNext()) {
            secPubIt.next();
            secSize++;
        }

        int pubSize = 0;
        Iterator<PGPPublicKey> pubPubIt = pub.getPublicKeys();
        while (pubPubIt.hasNext()) {
            pubPubIt.next();
            pubSize++;
        }

        assertEquals(secSize, pubSize);
    }
}
