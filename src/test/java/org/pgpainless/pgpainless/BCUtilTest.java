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

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertNull;
import static junit.framework.TestCase.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Test;
import org.pgpainless.pgpainless.key.generation.type.length.RsaLength;
import org.pgpainless.pgpainless.util.BCUtil;

public class BCUtilTest extends AbstractPGPainlessTest {

    private static final Logger LOGGER = Logger.getLogger(BCUtil.class.getName());

    @Test
    public void keyRingToCollectionTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sec = PGPainless.generateKeyRing().simpleEcKeyRing("donald@duck.tails");
        PGPPublicKeyRing pub = BCUtil.publicKeyRingFromSecretKeyRing(sec);

        LOGGER.log(Level.INFO, "Main ID: " + sec.getPublicKey().getKeyID() + " " + pub.getPublicKey().getKeyID());

        int secSize = 0;
        Iterator<PGPPublicKey> secPubIt = sec.getPublicKeys();
        while (secPubIt.hasNext()) {
            PGPPublicKey k = secPubIt.next();
            LOGGER.log(Level.INFO, "" + k.getKeyID() + " " + k.isEncryptionKey() + " " + k.isMasterKey());
            secSize++;
        }

        LOGGER.log(Level.INFO, "After BCUtil.publicKeyRingFromSecretKeyRing()");
        int pubSize = 0;
        Iterator<PGPPublicKey> pubPubIt = pub.getPublicKeys();
        while (pubPubIt.hasNext()) {
            PGPPublicKey k = pubPubIt.next();
            LOGGER.log(Level.INFO, "" + k.getKeyID() + " " + k.isEncryptionKey() + " " + k.isMasterKey());
            pubSize++;
        }

        LOGGER.log(Level.INFO, " Pub: " + pubSize + " Sec: " + secSize);
        assertEquals(secSize, pubSize);

        PGPSecretKeyRingCollection secCol = BCUtil.keyRingsToKeyRingCollection(sec);

        int secColSize = 0;
        Iterator<PGPSecretKeyRing> secColIt = secCol.getKeyRings();
        while (secColIt.hasNext()) {
            PGPSecretKeyRing r = secColIt.next();
            LOGGER.log(Level.INFO, "" + r.getPublicKey().getKeyID());
            secColSize++;
        }

        LOGGER.log(Level.INFO, "SecCol: " + secColSize);

        PGPPublicKeyRingCollection pubCol = BCUtil.keyRingsToKeyRingCollection(pub);

        int pubColSize = 0;
        Iterator<PGPPublicKeyRing> pubColIt = pubCol.getKeyRings();
        while (pubColIt.hasNext()) {
            PGPPublicKeyRing r = pubColIt.next();
            LOGGER.log(Level.INFO, "" + r.getPublicKey().getKeyID());
            pubColSize++;
        }

        LOGGER.log(Level.INFO, "PubCol: " + pubColSize);
    }

    @Test
    public void removeUnsignedKeysTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().simpleRsaKeyRing("alice@wonderland.lit", RsaLength._1024);
        PGPSecretKeyRing mallory = PGPainless.generateKeyRing().simpleEcKeyRing("mallory@mall.ory");

        PGPSecretKey subKey = null;
        Iterator<PGPSecretKey> sit = mallory.getSecretKeys();
        while (sit.hasNext()) {
            PGPSecretKey s = sit.next();
            if (!s.isMasterKey()) {
                subKey = s;
                break;
            }
        }

        assertNotNull(subKey);

        PGPSecretKeyRing alice_mallory = PGPSecretKeyRing.insertSecretKey(alice, subKey);

        // Check, if alice_mallory contains mallory's key
        assertNotNull(alice_mallory.getSecretKey(subKey.getKeyID()));

        PGPSecretKeyRing cleaned = BCUtil.removeUnassociatedKeysFromKeyRing(alice_mallory, alice.getPublicKey());
        assertNull(cleaned.getSecretKey(subKey.getKeyID()));
    }

    @Test
    public void removeUnsignedKeysECTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");

        PGPSecretKeyRing after = BCUtil.removeUnassociatedKeysFromKeyRing(alice, alice.getPublicKey());

        assertTrue(Arrays.equals(alice.getEncoded(), after.getEncoded()));
    }
}
