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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.util.KeyRingUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BCUtilTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(BCUtilTest.class);

    @Test
    public void keyRingToCollectionTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing sec = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072), KeyFlag.ENCRYPT_COMMS).build())
                .withPrimaryKey(KeySpec.getBuilder(
                        KeyType.RSA(RsaLength._3072),
                                KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .build())
                .withPrimaryUserId("donald@duck.tails").withoutPassphrase().build();

        PGPPublicKeyRing pub = KeyRingUtils.publicKeyRingFrom(sec);

        assertEquals(sec.getPublicKey().getKeyID(), pub.getPublicKey().getKeyID());

        int secSize = 1;
        Iterator<PGPPublicKey> secPubIt = sec.getPublicKeys();
        while (secPubIt.hasNext()) {
            PGPPublicKey k = secPubIt.next();
            LOGGER.debug("Index {}, keyId {}, isEncryptionKey={}, isPrimary={}", secSize, k.getKeyID(), k.isEncryptionKey(), k.isMasterKey());
            secSize++;
        }

        LOGGER.debug("After BCUtil.publicKeyRingFromSecretKeyRing()");
        int pubSize = 1;
        Iterator<PGPPublicKey> pubPubIt = pub.getPublicKeys();
        while (pubPubIt.hasNext()) {
            PGPPublicKey k = pubPubIt.next();
            LOGGER.debug("Index {}, keyId {}, isEncryptionKey={}, isPrimary={}", pubSize, k.getKeyID(), k.isEncryptionKey(), k.isMasterKey());
            pubSize++;
        }

        assertEquals(secSize, pubSize);

        PGPSecretKeyRingCollection secCol = KeyRingUtils.keyRingsToKeyRingCollection(sec);

        int secColSize = 0;
        Iterator<PGPSecretKeyRing> secColIt = secCol.getKeyRings();
        while (secColIt.hasNext()) {
            PGPSecretKeyRing r = secColIt.next();
            LOGGER.debug("{}", r.getPublicKey().getKeyID());
            secColSize++;
        }

        PGPPublicKeyRingCollection pubCol = KeyRingUtils.keyRingsToKeyRingCollection(pub);

        int pubColSize = 0;
        Iterator<PGPPublicKeyRing> pubColIt = pubCol.getKeyRings();
        while (pubColIt.hasNext()) {
            PGPPublicKeyRing r = pubColIt.next();
            LOGGER.debug("{}", r.getPublicKey().getKeyID());
            pubColSize++;
        }

        assertEquals(pubColSize, secColSize);
    }
}
