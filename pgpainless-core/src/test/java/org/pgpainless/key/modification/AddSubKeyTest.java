// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class AddSubKeyTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testAddSubKey()
            throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        List<Long> keyIdsBefore = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = secretKeys.getPublicKeys(); it.hasNext(); ) {
            keyIdsBefore.add(it.next().getKeyID());
        }

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addSubKey(
                        KeySpec.getBuilder(ECDSA.fromCurve(EllipticCurve._P256), KeyFlag.SIGN_DATA).build(),
                        Passphrase.fromPassword("subKeyPassphrase"),
                        PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("password123")))
                .done();

        List<Long> keyIdsAfter = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = secretKeys.getPublicKeys(); it.hasNext(); ) {
            keyIdsAfter.add(it.next().getKeyID());
        }
        assertNotEquals(keyIdsAfter, keyIdsBefore);

        keyIdsAfter.removeAll(keyIdsBefore);
        long subKeyId = keyIdsAfter.get(0);

        PGPSecretKey subKey = secretKeys.getSecretKey(subKeyId);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockEachKeyWith(
                Passphrase.fromPassword("subKeyPassphrase"), secretKeys);
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(subKey, protector);

        KeyRingInfo info = new KeyRingInfo(secretKeys);
        assertEquals(Collections.singletonList(KeyFlag.SIGN_DATA), info.getKeyFlagsOf(subKeyId));
    }
}
