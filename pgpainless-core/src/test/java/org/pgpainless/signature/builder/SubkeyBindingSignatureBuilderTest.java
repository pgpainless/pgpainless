// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.Passphrase;

public class SubkeyBindingSignatureBuilderTest {

    @Test
    public void testBindSubkeyWithCustomNotation() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>", "passphrase");
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        List<PGPPublicKey> previousSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.ANY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword("passphrase"), secretKey);

        PGPSecretKeyRing tempSubkeyRing = PGPainless.generateKeyRing()
                .modernKeyRing("Subkeys", null);
        PGPPublicKey subkeyPub = PGPainless.inspectKeyRing(tempSubkeyRing)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0);
        PGPSecretKey subkeySec = tempSubkeyRing.getSecretKey(subkeyPub.getKeyID());

        PGPSignature binding = SignatureBuilder.bindNonSigningSubkey(
                secretKey.getSecretKey(), protector,
                new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets subpackets) {
                        subpackets.addNotationData(false, "testnotation@pgpainless.org", "hello-world");
                    }
                }, KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                .build(subkeyPub);

        subkeyPub = PGPPublicKey.addCertification(subkeyPub, binding);
        subkeySec = PGPSecretKey.replacePublicKey(subkeySec, subkeyPub);
        secretKey = PGPSecretKeyRing.insertSecretKey(secretKey, subkeySec);

        info = PGPainless.inspectKeyRing(secretKey);
        List<PGPPublicKey> nextSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.ANY);
        assertEquals(previousSubkeys.size() + 1, nextSubkeys.size());
        subkeyPub = secretKey.getPublicKey(subkeyPub.getKeyID());
        Iterator<PGPSignature> newBindingSigs = subkeyPub.getSignaturesForKeyID(secretKey.getPublicKey().getKeyID());
        PGPSignature bindingSig = newBindingSigs.next();
        assertNotNull(bindingSig);
        List<NotationData> notations = SignatureSubpacketsUtil.getHashedNotationData(bindingSig);

        assertEquals(1, notations.size());
        assertEquals("testnotation@pgpainless.org", notations.get(0).getNotationName());
        assertEquals("hello-world", notations.get(0).getNotationValue());
    }
}
