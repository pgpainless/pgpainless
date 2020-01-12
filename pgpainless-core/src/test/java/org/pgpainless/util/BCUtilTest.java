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
package org.pgpainless.util;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.RSA_GENERAL;
import org.pgpainless.key.generation.type.length.RsaLength;

public class BCUtilTest {

    private static final Logger LOGGER = Logger.getLogger(BCUtil.class.getName());

    @Test
    public void keyRingToCollectionTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing ring = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(RSA_GENERAL.withLength(RsaLength._3072)).withDefaultKeyFlags().withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(RSA_GENERAL.withLength(RsaLength._3072)).withDefaultKeyFlags().withDefaultAlgorithms())
                .withPrimaryUserId("donald@duck.tails").withoutPassphrase().build();
        PGPSecretKeyRing sec = ring.getSecretKeys();
        PGPPublicKeyRing pub = ring.getPublicKeys();

        LOGGER.log(Level.FINER, "Main ID: " + sec.getPublicKey().getKeyID() + " " + pub.getPublicKey().getKeyID());

        int secSize = 1;
        Iterator<PGPPublicKey> secPubIt = sec.getPublicKeys();
        while (secPubIt.hasNext()) {
            PGPPublicKey k = secPubIt.next();
            LOGGER.log(Level.FINER, secSize + " " + k.getKeyID() + " " + k.isEncryptionKey() + " " + k.isMasterKey());
            secSize++;
        }

        LOGGER.log(Level.FINER, "After BCUtil.publicKeyRingFromSecretKeyRing()");
        int pubSize = 1;
        Iterator<PGPPublicKey> pubPubIt = pub.getPublicKeys();
        while (pubPubIt.hasNext()) {
            PGPPublicKey k = pubPubIt.next();
            LOGGER.log(Level.FINER, pubSize + " " + k.getKeyID() + " " + k.isEncryptionKey() + " " + k.isMasterKey());
            pubSize++;
        }

        assertEquals(secSize, pubSize);

        PGPSecretKeyRingCollection secCol = BCUtil.keyRingsToKeyRingCollection(sec);

        int secColSize = 0;
        Iterator<PGPSecretKeyRing> secColIt = secCol.getKeyRings();
        while (secColIt.hasNext()) {
            PGPSecretKeyRing r = secColIt.next();
            LOGGER.log(Level.FINER, "" + r.getPublicKey().getKeyID());
            secColSize++;
        }

        LOGGER.log(Level.FINER, "SecCol: " + secColSize);

        PGPPublicKeyRingCollection pubCol = BCUtil.keyRingsToKeyRingCollection(pub);

        int pubColSize = 0;
        Iterator<PGPPublicKeyRing> pubColIt = pubCol.getKeyRings();
        while (pubColIt.hasNext()) {
            PGPPublicKeyRing r = pubColIt.next();
            LOGGER.log(Level.FINER, "" + r.getPublicKey().getKeyID());
            pubColSize++;
        }

        LOGGER.log(Level.FINER, "PubCol: " + pubColSize);
    }

    @Test
    public void removeUnsignedKeysTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        @SuppressWarnings("deprecation")
        PGPKeyRing alice = PGPainless.generateKeyRing().simpleRsaKeyRing("alice@wonderland.lit", RsaLength._1024);
        PGPKeyRing mallory = PGPainless.generateKeyRing().simpleEcKeyRing("mallory@mall.ory");

        PGPSecretKey subKey = null;
        Iterator<PGPSecretKey> sit = mallory.getSecretKeys().getSecretKeys();
        while (sit.hasNext()) {
            PGPSecretKey s = sit.next();
            if (!s.isMasterKey()) {
                subKey = s;
                break;
            }
        }

        TestCase.assertNotNull(subKey);

        PGPSecretKeyRing alice_mallory = PGPSecretKeyRing.insertSecretKey(alice.getSecretKeys(), subKey);

        // Check, if alice_mallory contains mallory's key
        TestCase.assertNotNull(alice_mallory.getSecretKey(subKey.getKeyID()));

        PGPSecretKeyRing cleaned = BCUtil.removeUnassociatedKeysFromKeyRing(alice_mallory, alice.getPublicKeys().getPublicKey());
        TestCase.assertNull(cleaned.getSecretKey(subKey.getKeyID()));
    }

    @Test
    public void removeUnsignedKeysECTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing ring = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");
        PGPPublicKeyRing publicKeys = ring.getPublicKeys();
        PGPSecretKeyRing secretKeys = ring.getSecretKeys();
        PGPSecretKeyRing secCleaned = ring.getSecretKeys();

        assertArrayEquals(secretKeys.getEncoded(), secCleaned.getEncoded());

        PGPPublicKeyRing pubCleaned = BCUtil.removeUnassociatedKeysFromKeyRing(publicKeys, publicKeys.getPublicKey());

        assertArrayEquals(publicKeys.getEncoded(), pubCleaned.getEncoded());

    }
}
