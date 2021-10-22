// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class SubkeyBindingSignatureBuilderTest {

    @Test
    public void testBindSubkeyWithCustomNotation() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>", "passphrase");
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        List<PGPPublicKey> previousSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword("passphrase"), secretKey);

        PGPSecretKeyRing tempSubkeyRing = PGPainless.generateKeyRing()
                .modernKeyRing("Subkeys", null);
        PGPPublicKey subkey = PGPainless.inspectKeyRing(tempSubkeyRing)
                .getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS).get(0);

        SubkeyBindingSignatureBuilder skbb = new SubkeyBindingSignatureBuilder(SignatureType.SUBKEY_BINDING, secretKey.getSecretKey(), protector);
        skbb.getHashedSubpackets().addNotationData(false, "testnotation@pgpainless.org", "hello-world");
        skbb.getHashedSubpackets().setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);
        PGPSignature binding = skbb.build(subkey);
        subkey = PGPPublicKey.addCertification(subkey, binding);
        PGPSecretKey secSubkey = tempSubkeyRing.getSecretKey(subkey.getKeyID());
        secSubkey = PGPSecretKey.replacePublicKey(secSubkey, subkey);
        secretKey = PGPSecretKeyRing.insertSecretKey(secretKey, secSubkey);

        info = PGPainless.inspectKeyRing(secretKey);
        List<PGPPublicKey> nextSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS);
        assertEquals(previousSubkeys.size() + 1, nextSubkeys.size());
    }
}
