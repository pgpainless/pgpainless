// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.util.Passphrase;

public class KeyGenerationSubpacketsTest {

    @Test
    public void verifyDefaultSubpacketsForUserIdSignatures()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice", null);

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        PGPSignature userIdSig = info.getLatestUserIdCertification("Alice");
        assertNotNull(userIdSig);
        int keyFlags = userIdSig.getHashedSubPackets().getKeyFlags();
        int[] preferredHashAlgorithms = userIdSig.getHashedSubPackets().getPreferredHashAlgorithms();
        int[] preferredSymmetricAlgorithms = userIdSig.getHashedSubPackets().getPreferredSymmetricAlgorithms();
        int[] preferredCompressionAlgorithms = userIdSig.getHashedSubPackets().getPreferredCompressionAlgorithms();
        assureSignatureHasDefaultSubpackets(userIdSig, secretKeys, KeyFlag.CERTIFY_OTHER);
        assertTrue(userIdSig.getHashedSubPackets().isPrimaryUserID());

        assertEquals("Alice", info.getPrimaryUserId());

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Bob",
                        new SelfSignatureSubpackets.Callback() {
                            @Override
                            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                                hashedSubpackets.setPrimaryUserId();
                            }
                        },
                        SecretKeyRingProtector.unprotectedKeys())
                .addUserId("Alice", SecretKeyRingProtector.unprotectedKeys())
                .done();

        info = PGPainless.inspectKeyRing(secretKeys);

        userIdSig = info.getLatestUserIdCertification("Alice");
        assertNotNull(userIdSig);
        assureSignatureHasDefaultSubpackets(userIdSig, secretKeys, KeyFlag.CERTIFY_OTHER);
        assertFalse(userIdSig.getHashedSubPackets().isPrimaryUserID());
        assertEquals(keyFlags, userIdSig.getHashedSubPackets().getKeyFlags());
        assertArrayEquals(preferredHashAlgorithms, userIdSig.getHashedSubPackets().getPreferredHashAlgorithms());
        assertArrayEquals(preferredSymmetricAlgorithms, userIdSig.getHashedSubPackets().getPreferredSymmetricAlgorithms());
        assertArrayEquals(preferredCompressionAlgorithms, userIdSig.getHashedSubPackets().getPreferredCompressionAlgorithms());

        userIdSig = info.getLatestUserIdCertification("Bob");
        assertNotNull(userIdSig);
        assureSignatureHasDefaultSubpackets(userIdSig, secretKeys, KeyFlag.CERTIFY_OTHER);
        assertTrue(userIdSig.getHashedSubPackets().isPrimaryUserID());
        assertArrayEquals(preferredHashAlgorithms, userIdSig.getHashedSubPackets().getPreferredHashAlgorithms());
        assertArrayEquals(preferredSymmetricAlgorithms, userIdSig.getHashedSubPackets().getPreferredSymmetricAlgorithms());
        assertArrayEquals(preferredCompressionAlgorithms, userIdSig.getHashedSubPackets().getPreferredCompressionAlgorithms());

        assertEquals("Bob", info.getPrimaryUserId());

        // wait one sec so that it is clear that the new certification for alice is the most recent one
        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Alice", new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setPrimaryUserId();
                        hashedSubpackets.setPreferredHashAlgorithms(HashAlgorithm.SHA1);
                    }
                }, SecretKeyRingProtector.unprotectedKeys())
                .done();
        info = PGPainless.inspectKeyRing(secretKeys);
        assertEquals("Alice", info.getPrimaryUserId());
        assertEquals(Collections.singleton(HashAlgorithm.SHA1), info.getPreferredHashAlgorithms("Alice"));
    }

    @Test
    public void verifyDefaultSubpacketsForSubkeyBindingSignatures()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        List<PGPPublicKey> keysBefore = info.getPublicKeys();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addSubKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA).build(),
                        Passphrase.emptyPassphrase(), SecretKeyRingProtector.unprotectedKeys())
                .done();


        info = PGPainless.inspectKeyRing(secretKeys);
        List<PGPPublicKey> keysAfter = new ArrayList<>(info.getPublicKeys());
        keysAfter.removeAll(keysBefore);
        assertEquals(1, keysAfter.size());
        PGPPublicKey newSigningKey = keysAfter.get(0);

        PGPSignature bindingSig = info.getCurrentSubkeyBindingSignature(newSigningKey.getKeyID());
        assertNotNull(bindingSig);
        assureSignatureHasDefaultSubpackets(bindingSig, secretKeys, KeyFlag.SIGN_DATA);
        assertNotNull(bindingSig.getHashedSubPackets().getEmbeddedSignatures().get(0));

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addSubKey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS).build(),
                        Passphrase.emptyPassphrase(),
                        new SelfSignatureSubpackets.Callback() {
                            @Override
                            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                                hashedSubpackets.setIssuerFingerprint((IssuerFingerprint) null);
                            }
                        }, SecretKeyRingProtector.unprotectedKeys())
                .done();

        info = PGPainless.inspectKeyRing(secretKeys);
        keysAfter = new ArrayList<>(info.getPublicKeys());
        keysAfter.removeAll(keysBefore);
        keysAfter.remove(newSigningKey);
        assertEquals(1, keysAfter.size());
        PGPPublicKey newEncryptionKey = keysAfter.get(0);
        bindingSig = info.getCurrentSubkeyBindingSignature(newEncryptionKey.getKeyID());
        assertNotNull(bindingSig);
        assertNull(bindingSig.getHashedSubPackets().getIssuerFingerprint());
        assertEquals(KeyFlag.toBitmask(KeyFlag.ENCRYPT_COMMS), bindingSig.getHashedSubPackets().getKeyFlags());
    }

    private void assureSignatureHasDefaultSubpackets(PGPSignature signature, PGPSecretKeyRing secretKeys, KeyFlag... keyFlags) {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        assertNotNull(hashedSubpackets.getIssuerFingerprint());
        assertEquals(secretKeys.getPublicKey().getKeyID(), hashedSubpackets.getIssuerKeyID());
        assertArrayEquals(
                secretKeys.getPublicKey().getFingerprint(),
                hashedSubpackets.getIssuerFingerprint().getFingerprint());
        assertEquals(hashedSubpackets.getKeyFlags(), KeyFlag.toBitmask(keyFlags));
    }
}
