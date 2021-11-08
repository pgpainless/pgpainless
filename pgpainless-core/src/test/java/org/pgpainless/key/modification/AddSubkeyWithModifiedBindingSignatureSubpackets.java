// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.Passphrase;

public class AddSubkeyWithModifiedBindingSignatureSubpackets {

    @Test
    public void bindEncryptionSubkeyAndModifyBindingSignatureHashedSubpackets() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>", null);
        KeyRingInfo before = PGPainless.inspectKeyRing(secretKeys);

        PGPSecretKey secretSubkey = KeyRingBuilder.generatePGPSecretKey(
                KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS).build(),
                Passphrase.emptyPassphrase(), false);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addSubKey(secretSubkey, new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setKeyExpirationTime(true, 1000);
                        hashedSubpackets.addNotationData(false, "test@test.test", "test");
                    }
                }, null, SecretKeyRingProtector.unprotectedKeys(), protector, KeyFlag.ENCRYPT_COMMS)
                .done();

        KeyRingInfo after = PGPainless.inspectKeyRing(secretKeys);

        List<PGPPublicKey> encryptionKeys = after.getEncryptionSubkeys(EncryptionPurpose.COMMUNICATIONS);
        encryptionKeys.removeAll(before.getEncryptionSubkeys(EncryptionPurpose.COMMUNICATIONS));
        assertFalse(encryptionKeys.isEmpty());
        assertEquals(1, encryptionKeys.size());

        PGPPublicKey newKey = encryptionKeys.get(0);
        JUtils.assertEquals(new Date().getTime() + 1000 * 1000, after.getSubkeyExpirationDate(new OpenPgpV4Fingerprint(newKey)).getTime(), 2000);
        assertTrue(newKey.getSignatures().hasNext());
        PGPSignature binding = newKey.getSignatures().next();
        List<NotationData> notations = SignatureSubpacketsUtil.getHashedNotationData(binding);
        assertEquals(1, notations.size());
        assertEquals("test@test.test", notations.get(0).getNotationName());
    }
}
