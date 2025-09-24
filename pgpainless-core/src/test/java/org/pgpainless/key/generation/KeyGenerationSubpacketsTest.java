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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.util.Passphrase;

public class KeyGenerationSubpacketsTest {

    @Test
    public void verifyDefaultSubpacketsForUserIdSignatures()
            throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice");
        Date plus1Sec = new Date(secretKeys.getPrimarySecretKey().getCreationTime().getTime() + 1000);
        KeyRingInfo info = api.inspect(secretKeys);
        PGPSignature userIdSig = info.getLatestUserIdCertification("Alice");
        assertNotNull(userIdSig);
        int keyFlags = userIdSig.getHashedSubPackets().getKeyFlags();
        int[] preferredHashAlgorithms = userIdSig.getHashedSubPackets().getPreferredHashAlgorithms();
        int[] preferredSymmetricAlgorithms = userIdSig.getHashedSubPackets().getPreferredSymmetricAlgorithms();
        int[] preferredCompressionAlgorithms = userIdSig.getHashedSubPackets().getPreferredCompressionAlgorithms();
        assureSignatureHasDefaultSubpackets(userIdSig, secretKeys, KeyFlag.CERTIFY_OTHER);
        assertTrue(userIdSig.getHashedSubPackets().isPrimaryUserID());

        assertEquals("Alice", info.getPrimaryUserId());

        secretKeys = api.modify(secretKeys, plus1Sec)
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

        info = api.inspect(secretKeys, plus1Sec);

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

        Date now = plus1Sec;
        Date t1 = new Date(now.getTime() + 1000 * 60 * 60);
        secretKeys = api.modify(secretKeys, t1)
                .addUserId("Alice", new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setPrimaryUserId();
                        hashedSubpackets.setPreferredHashAlgorithms(HashAlgorithm.SHA1);
                    }
                }, SecretKeyRingProtector.unprotectedKeys())
                .done();
        info = api.inspect(secretKeys, t1);
        assertEquals("Alice", info.getPrimaryUserId());
        assertEquals(Collections.singleton(HashAlgorithm.SHA1), info.getPreferredHashAlgorithms("Alice"));
    }

    @Test
    public void verifyDefaultSubpacketsForSubkeyBindingSignatures()
            throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice");
        KeyRingInfo info = api.inspect(secretKeys);
        List<OpenPGPCertificate.OpenPGPComponentKey> keysBefore = info.getPublicKeys();

        secretKeys = api.modify(secretKeys)
                .addSubKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA).build(),
                        Passphrase.emptyPassphrase(), SecretKeyRingProtector.unprotectedKeys())
                .done();


        info = api.inspect(secretKeys);
        List<OpenPGPCertificate.OpenPGPComponentKey> keysAfter = new ArrayList<>(info.getPublicKeys());
        keysAfter.removeAll(keysBefore);
        assertEquals(1, keysAfter.size());
        OpenPGPCertificate.OpenPGPComponentKey newSigningKey = keysAfter.get(0);

        PGPSignature bindingSig = info.getCurrentSubkeyBindingSignature(newSigningKey.getKeyIdentifier());
        assertNotNull(bindingSig);
        assureSignatureHasDefaultSubpackets(bindingSig, secretKeys, KeyFlag.SIGN_DATA);
        assertNotNull(bindingSig.getHashedSubPackets().getEmbeddedSignatures().get(0));

        secretKeys = api.modify(secretKeys)
                .addSubKey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS).build(),
                        Passphrase.emptyPassphrase(),
                        new SelfSignatureSubpackets.Callback() {
                            @Override
                            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                                hashedSubpackets.setIssuerFingerprint((IssuerFingerprint) null);
                            }
                        }, SecretKeyRingProtector.unprotectedKeys())
                .done();

        info = api.inspect(secretKeys);
        keysAfter = new ArrayList<>(info.getPublicKeys());
        keysAfter.removeAll(keysBefore);
        keysAfter.remove(newSigningKey);
        assertEquals(1, keysAfter.size());
        OpenPGPCertificate.OpenPGPComponentKey newEncryptionKey = keysAfter.get(0);
        bindingSig = info.getCurrentSubkeyBindingSignature(newEncryptionKey.getKeyIdentifier());
        assertNotNull(bindingSig);
        assertNull(bindingSig.getHashedSubPackets().getIssuerFingerprint());
        assertEquals(KeyFlag.toBitmask(KeyFlag.ENCRYPT_COMMS), bindingSig.getHashedSubPackets().getKeyFlags());
    }

    private void assureSignatureHasDefaultSubpackets(PGPSignature signature, OpenPGPKey secretKeys, KeyFlag... keyFlags) {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        assertNotNull(hashedSubpackets.getIssuerFingerprint());
        assertEquals(secretKeys.getKeyIdentifier().getKeyId(), hashedSubpackets.getIssuerKeyID());
        assertArrayEquals(
                secretKeys.getFingerprint(),
                hashedSubpackets.getIssuerFingerprint().getFingerprint());
        assertEquals(hashedSubpackets.getKeyFlags(), KeyFlag.toBitmask(keyFlags));
    }
}
