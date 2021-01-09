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
package org.pgpainless.key.selection.key;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.key.selection.key.impl.HasAllKeyFlagSelectionStrategy;
import org.pgpainless.key.selection.key.impl.HasAnyKeyFlagSelectionStrategy;

public class KeyFlagBasedSelectionStrategyTest {

    @Test
    public void testKeyFlagSelectors() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.ECDSA(EllipticCurve._P256))
                        .withKeyFlags(KeyFlag.SIGN_DATA)
                        .withDefaultAlgorithms())
                .withSubKey(KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.AUTHENTICATION)
                        .withDefaultAlgorithms())
                .withPrimaryUserId("test@test.test")
                .withoutPassphrase().build();

        Iterator<PGPSecretKey> iterator = secretKeys.iterator();
        // CERTIFY_OTHER and AUTHENTICATION
        PGPSecretKey s_primaryKey = iterator.next();
        // SIGN_DATA
        PGPSecretKey s_signingKey = iterator.next();
        // ENCRYPT_COMMS
        PGPSecretKey s_encryptionKey = iterator.next();

        HasAllKeyFlagSelectionStrategy.SecretKey s_certifyOther =
                new HasAllKeyFlagSelectionStrategy.SecretKey(KeyFlag.CERTIFY_OTHER);
        HasAllKeyFlagSelectionStrategy.SecretKey s_encryptComms =
                new HasAllKeyFlagSelectionStrategy.SecretKey(KeyFlag.ENCRYPT_COMMS);
        HasAllKeyFlagSelectionStrategy.SecretKey s_encryptCommsEncryptStorage =
                new HasAllKeyFlagSelectionStrategy.SecretKey(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);
        HasAnyKeyFlagSelectionStrategy.SecretKey s_anyEncryptCommsEncryptStorage =
                new HasAnyKeyFlagSelectionStrategy.SecretKey(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);

        assertTrue(s_certifyOther.accept(s_primaryKey));
        assertFalse(s_certifyOther.accept(s_encryptionKey));
        assertFalse(s_certifyOther.accept(s_signingKey));

        assertTrue(s_encryptComms.accept(s_encryptionKey));
        assertFalse(s_encryptComms.accept(s_primaryKey));
        assertFalse(s_encryptComms.accept(s_signingKey));

        assertFalse(s_encryptCommsEncryptStorage.accept(s_encryptionKey),
                "Must not accept the key, as it only carries ENCRYPT_COMMS, but not ENCRYPT_STORAGE");
        assertFalse(s_encryptCommsEncryptStorage.accept(s_primaryKey));
        assertFalse(s_encryptCommsEncryptStorage.accept(s_signingKey));

        assertTrue(s_anyEncryptCommsEncryptStorage.accept(s_encryptionKey));
        assertFalse(s_anyEncryptCommsEncryptStorage.accept(s_primaryKey));
        assertFalse(s_anyEncryptCommsEncryptStorage.accept(s_signingKey));

        PGPPublicKey p_primaryKey = s_primaryKey.getPublicKey();
        PGPPublicKey p_encryptionKey = s_encryptionKey.getPublicKey();
        PGPPublicKey p_signingKey = s_signingKey.getPublicKey();

        HasAllKeyFlagSelectionStrategy.PublicKey p_certifyOther =
                new HasAllKeyFlagSelectionStrategy.PublicKey(KeyFlag.CERTIFY_OTHER);
        HasAllKeyFlagSelectionStrategy.PublicKey p_encryptComms =
                new HasAllKeyFlagSelectionStrategy.PublicKey(KeyFlag.ENCRYPT_COMMS);
        HasAllKeyFlagSelectionStrategy.PublicKey p_encryptCommsEncryptStorage =
                new HasAllKeyFlagSelectionStrategy.PublicKey(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);
        HasAnyKeyFlagSelectionStrategy.PublicKey p_anyEncryptCommsEncryptStorage =
                new HasAnyKeyFlagSelectionStrategy.PublicKey(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);

        assertTrue(p_certifyOther.accept(p_primaryKey));
        assertFalse(p_certifyOther.accept(p_encryptionKey));
        assertFalse(p_certifyOther.accept(p_signingKey));

        assertTrue(p_encryptComms.accept(p_encryptionKey));
        assertFalse(p_encryptComms.accept(p_primaryKey));
        assertFalse(p_encryptComms.accept(p_signingKey));

        assertFalse(p_encryptCommsEncryptStorage.accept(p_encryptionKey),
                "Must not accept the key, as it only carries ENCRYPT_COMMS, but not ENCRYPT_STORAGE");
        assertFalse(p_encryptCommsEncryptStorage.accept(p_primaryKey));
        assertFalse(p_encryptCommsEncryptStorage.accept(p_signingKey));

        assertTrue(p_anyEncryptCommsEncryptStorage.accept(p_encryptionKey));
        assertFalse(p_anyEncryptCommsEncryptStorage.accept(p_primaryKey));
        assertFalse(p_anyEncryptCommsEncryptStorage.accept(p_signingKey));
    }
}
