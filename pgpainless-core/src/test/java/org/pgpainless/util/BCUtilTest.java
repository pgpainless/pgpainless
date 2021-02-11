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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
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
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.util.KeyRingUtils;

public class BCUtilTest {

    private static final Logger LOGGER = Logger.getLogger(BCUtil.class.getName());

    @Test
    public void keyRingToCollectionTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sec = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .withDefaultAlgorithms())
                .withPrimaryUserId("donald@duck.tails").withoutPassphrase().build();

        PGPPublicKeyRing pub = KeyRingUtils.publicKeyRingFrom(sec);

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
    public void getMasterKeyFromRingTest() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        PGPPublicKey primaryKey = BCUtil.getMasterKeyFrom(secretKeys);

        assertNotNull(primaryKey);
        assertEquals(TestKeys.CRYPTIE_FINGERPRINT, new OpenPgpV4Fingerprint(primaryKey));
    }
}
