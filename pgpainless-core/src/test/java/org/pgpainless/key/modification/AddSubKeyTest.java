// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.OpenPGPKey;
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
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class AddSubKeyTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testAddSubKey()
            throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();

        List<KeyIdentifier> keyIdentifiersBefore = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = secretKeys.getPGPSecretKeyRing().getPublicKeys(); it.hasNext(); ) {
            keyIdentifiersBefore.add(it.next().getKeyIdentifier());
        }

        secretKeys = api.modify(secretKeys)
                .addSubKey(
                        KeySpec.getBuilder(ECDSA.fromCurve(EllipticCurve._P256), KeyFlag.SIGN_DATA).build(),
                        Passphrase.fromPassword("subKeyPassphrase"),
                        PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("password123")))
                .done();

        List<KeyIdentifier> keyIdentifiersAfter = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = secretKeys.getPGPSecretKeyRing().getPublicKeys(); it.hasNext(); ) {
            keyIdentifiersAfter.add(it.next().getKeyIdentifier());
        }
        assertNotEquals(keyIdentifiersAfter, keyIdentifiersBefore);

        keyIdentifiersAfter.removeAll(keyIdentifiersBefore);
        KeyIdentifier subKeyIdentifier = keyIdentifiersAfter.get(0);

        OpenPGPKey.OpenPGPSecretKey subKey = secretKeys.getSecretKey(subKeyIdentifier);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockEachKeyWith(
                Passphrase.fromPassword("subKeyPassphrase"), secretKeys);
        UnlockSecretKey.unlockSecretKey(subKey, protector);

        KeyRingInfo info = api.inspect(secretKeys);
        assertEquals(Collections.singletonList(KeyFlag.SIGN_DATA), info.getKeyFlagsOf(subKeyIdentifier));
    }
}
