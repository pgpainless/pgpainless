// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.Passphrase;

public class SignatureSubpacketsTest {

    private static PGPPublicKeyRing keys;
    private static PGPPublicKey key;

    private SignatureSubpackets wrapper;

    @BeforeAll
    public static void setup() throws IOException {
        keys = TestKeys.getEmilPublicKeyRing();
        key = keys.getPublicKey();
    }

    @BeforeEach
    public void createWrapper() {
        wrapper = SignatureSubpackets.createHashedSubpackets(key);
    }

    @Test
    public void initialStateTest() {
        wrapper = new SignatureSubpackets();
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertNull(vector.getSignatureCreationTime());
    }

    @Test
    public void initialStateFromKeyTest() throws PGPException {
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(key.getKeyID(), vector.getIssuerKeyID());
        assertEquals(key.getVersion(), vector.getIssuerFingerprint().getKeyVersion());
        assertArrayEquals(key.getFingerprint(), vector.getIssuerFingerprint().getFingerprint());
        assertNull(vector.getSignatureCreationTime());

        assertEquals(0, vector.getKeyFlags());
        assertEquals(0, vector.getSignatureExpirationTime());
        assertNull(vector.getSignerUserID());
        assertFalse(vector.isPrimaryUserID());
        assertEquals(0, vector.getKeyExpirationTime());
        assertNull(vector.getPreferredCompressionAlgorithms());
        assertNull(vector.getPreferredSymmetricAlgorithms());
        assertNull(vector.getPreferredHashAlgorithms());
        assertEquals(0, vector.getNotationDataOccurrences().length);
        assertNull(vector.getIntendedRecipientFingerprint());
        assertNull(vector.getSubpacket(SignatureSubpacketTags.EXPORTABLE));
        assertNull(vector.getSubpacket(SignatureSubpacketTags.REVOCATION_KEY));
        assertNull(vector.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON));
        assertNull(vector.getSignatureTarget());
        assertNull(vector.getFeatures());
        assertNull(vector.getSubpacket(SignatureSubpacketTags.TRUST_SIG));
        assertTrue(vector.getEmbeddedSignatures().isEmpty());
    }

    @Test
    public void testNullKeyId() {
        wrapper.setIssuerKeyId(null);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(0, vector.getIssuerKeyID());
    }


    @Test
    public void testNullFingerprint() {
        wrapper.setIssuerFingerprint((IssuerFingerprint) null);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertNull(vector.getIssuerFingerprint());
    }

    @Test
    public void testAddNotationData() {
        wrapper.addNotationData(true, "critical@notation.data", "isCritical");
        wrapper.addNotationData(false, "noncrit@notation.data", "notCritical");
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        NotationData[] notationData = vector.getNotationDataOccurrences();
        assertEquals(2, notationData.length);
        NotationData first = notationData[0];
        assertTrue(first.isCritical());
        assertTrue(first.isHumanReadable());
        assertEquals("critical@notation.data", first.getNotationName());
        assertEquals("isCritical", first.getNotationValue());

        NotationData second = notationData[1];
        assertFalse(second.isCritical());
        assertTrue(second.isHumanReadable());
        assertEquals("noncrit@notation.data", second.getNotationName());
        assertEquals("notCritical", second.getNotationValue());

        wrapper.clearNotationData();
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getNotationDataOccurrences().length);

    }

    @Test
    public void testIntendedRecipientFingerprints() {
        wrapper.addIntendedRecipientFingerprint(key);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(1, vector.getSubpackets(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT).length);
        assertArrayEquals(key.getFingerprint(), vector.getIntendedRecipientFingerprint().getFingerprint());
        assertEquals(key.getVersion(), vector.getIntendedRecipientFingerprint().getKeyVersion());

        wrapper.clearIntendedRecipientFingerprints();
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getSubpackets(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT).length);
    }

    @Test
    public void testAddRevocationKeys() {
        Iterator<PGPPublicKey> keyIterator = keys.getPublicKeys();
        PGPPublicKey first = keyIterator.next();
        wrapper.addRevocationKey(first);
        assertTrue(keyIterator.hasNext());
        PGPPublicKey second = keyIterator.next();
        wrapper.addRevocationKey(false, true, second);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        SignatureSubpacket[] revKeys = vector.getSubpackets(SignatureSubpacketTags.REVOCATION_KEY);
        assertEquals(2, revKeys.length);
        RevocationKey r1 = (RevocationKey) revKeys[0];
        RevocationKey r2 = (RevocationKey) revKeys[1];

        assertTrue(r1.isCritical());
        assertArrayEquals(first.getFingerprint(), r1.getFingerprint());
        assertEquals(first.getAlgorithm(), r1.getAlgorithm());
        assertEquals((byte) 0x80, r1.getSignatureClass());

        assertFalse(r2.isCritical());
        assertArrayEquals(second.getFingerprint(), r2.getFingerprint());
        assertEquals(second.getAlgorithm(), r2.getAlgorithm());
        assertEquals((byte) (0x80 | 0x40), r2.getSignatureClass());

        wrapper.clearRevocationKeys();
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getSubpackets(SignatureSubpacketTags.REVOCATION_KEY).length);
    }

    @Test
    public void testSetKeyFlags() {
        wrapper.setKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA); // duplicates are removed
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(KeyFlag.toBitmask(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER), vector.getKeyFlags());
        assertTrue(vector.getSubpacket(SignatureSubpacketTags.KEY_FLAGS).isCritical());
    }

    @Test
    public void testSignatureExpirationTime() {
        Date now = new Date();
        long secondsInAWeek = 60 * 60 * 24 * 7;
        Date inAWeek = new Date(now.getTime() + 1000 * secondsInAWeek);
        wrapper.setSignatureExpirationTime(now, inAWeek);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(secondsInAWeek, vector.getSignatureExpirationTime());
    }

    @Test
    public void testSignatureExpirationTimeCannotBeNegative() {
        Date now = new Date();
        long secondsInAWeek = 60 * 60 * 24 * 7;
        Date oneWeekEarlier = new Date(now.getTime() - 1000 * secondsInAWeek);
        assertThrows(IllegalArgumentException.class, () -> wrapper.setSignatureExpirationTime(now, oneWeekEarlier));
    }

    @Test
    public void testSignerUserId() {
        String userId = "Alice <alice@pgpainless.org>";
        wrapper.setSignerUserId(userId);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(userId, vector.getSignerUserID());
    }

    @Test
    public void testSetPrimaryUserId() {
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertFalse(vector.isPrimaryUserID());

        wrapper.setPrimaryUserId();
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertTrue(vector.isPrimaryUserID());
    }

    @Test
    public void testSetKeyExpiration() {
        Date now = new Date();
        long secondsSinceKeyCreation = (now.getTime() - key.getCreationTime().getTime()) / 1000;
        wrapper.setKeyExpirationTime(key, now);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(secondsSinceKeyCreation, vector.getKeyExpirationTime());
    }

    @Test
    public void testSetKeyExpirationCannotBeNegative() {
        Date beforeKeyCreation = new Date(key.getCreationTime().getTime() - 10000);
        assertThrows(IllegalArgumentException.class, () -> wrapper.setKeyExpirationTime(key, beforeKeyCreation));
    }

    @Test
    public void testSetPreferredCompressionAlgorithms() {
        wrapper.setPreferredCompressionAlgorithms(CompressionAlgorithm.BZIP2, CompressionAlgorithm.ZIP, CompressionAlgorithm.BZIP2); // duplicates get removed
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        int[] ids = vector.getPreferredCompressionAlgorithms();
        assertEquals(2, ids.length);
        assertEquals(CompressionAlgorithm.BZIP2.getAlgorithmId(), ids[0]);
        assertEquals(CompressionAlgorithm.ZIP.getAlgorithmId(), ids[1]);

        wrapper.setPreferredCompressionAlgorithms(); // empty
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getPreferredCompressionAlgorithms().length);

        wrapper.setPreferredCompressionAlgorithms((PreferredAlgorithms) null);
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertNull(vector.getPreferredCompressionAlgorithms());

        assertThrows(IllegalArgumentException.class, () -> wrapper.setPreferredCompressionAlgorithms(
                new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_SYM_ALGS, true, new int[0])));
    }

    @Test
    public void testSetPreferredSymmetricKeyAlgorithms() {
        wrapper.setPreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128, SymmetricKeyAlgorithm.AES_128); // duplicates get removed
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        int[] ids = vector.getPreferredSymmetricAlgorithms();
        assertEquals(2, ids.length);
        assertEquals(SymmetricKeyAlgorithm.AES_192.getAlgorithmId(), ids[0]);
        assertEquals(SymmetricKeyAlgorithm.AES_128.getAlgorithmId(), ids[1]);

        wrapper.setPreferredSymmetricKeyAlgorithms(); // empty
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getPreferredSymmetricAlgorithms().length);

        wrapper.setPreferredSymmetricKeyAlgorithms((PreferredAlgorithms) null);
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertNull(vector.getPreferredCompressionAlgorithms());

        assertThrows(IllegalArgumentException.class, () -> wrapper.setPreferredSymmetricKeyAlgorithms(
                new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_HASH_ALGS, true, new int[0])));
    }

    @Test
    public void testSetPreferredHashAlgorithms() {
        wrapper.setPreferredHashAlgorithms(HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA512); // duplicates get removed
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        int[] ids = vector.getPreferredHashAlgorithms();
        assertEquals(2, ids.length);
        assertEquals(HashAlgorithm.SHA512.getAlgorithmId(), ids[0]);
        assertEquals(HashAlgorithm.SHA384.getAlgorithmId(), ids[1]);

        wrapper.setPreferredHashAlgorithms(); // empty
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getPreferredHashAlgorithms().length);

        wrapper.setPreferredHashAlgorithms((PreferredAlgorithms) null);
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertNull(vector.getPreferredHashAlgorithms());

        assertThrows(IllegalArgumentException.class, () -> wrapper.setPreferredHashAlgorithms(
                new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_COMP_ALGS, true, new int[0])));
    }

    @Test
    public void testSetExportable() {
        wrapper.setExportable(true, false);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        Exportable exportable = (Exportable) vector.getSubpacket(SignatureSubpacketTags.EXPORTABLE);
        assertTrue(exportable.isCritical());
        assertFalse(exportable.isExportable());

        wrapper.setExportable(false, true);
        vector = SignatureSubpacketsHelper.toVector(wrapper);

        exportable = (Exportable) vector.getSubpacket(SignatureSubpacketTags.EXPORTABLE);
        assertFalse(exportable.isCritical());
        assertTrue(exportable.isExportable());
    }

    @Test
    public void testSetRevocable() {
        wrapper.setRevocable(true, true);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        Revocable revocable = (Revocable) vector.getSubpacket(SignatureSubpacketTags.REVOCABLE);
        assertTrue(revocable.isCritical());
        assertTrue(revocable.isRevocable());

        wrapper.setRevocable(false, false);
        vector = SignatureSubpacketsHelper.toVector(wrapper);

        revocable = (Revocable) vector.getSubpacket(SignatureSubpacketTags.REVOCABLE);
        assertFalse(revocable.isCritical());
        assertFalse(revocable.isRevocable());
    }

    @Test
    public void testSetRevocationReason() {
        wrapper.setRevocationReason(RevocationAttributes.createKeyRevocation()
                .withReason(RevocationAttributes.Reason.KEY_RETIRED).withDescription("The key is too weak."));
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        assertEquals(1, vector.getSubpackets(SignatureSubpacketTags.REVOCATION_REASON).length);
        RevocationReason reason = (RevocationReason) vector.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON);
        assertEquals(RevocationAttributes.Reason.KEY_RETIRED.code(), reason.getRevocationReason());
        assertEquals("The key is too weak.", reason.getRevocationDescription());
    }

    @Test
    public void testSetSignatureTarget() {
        byte[] hash = new byte[20];
        new Random().nextBytes(hash);
        wrapper.setSignatureTarget(PublicKeyAlgorithm.requireFromId(key.getAlgorithm()), HashAlgorithm.SHA512, hash);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        SignatureTarget target = vector.getSignatureTarget();
        assertNotNull(target);
        assertEquals(key.getAlgorithm(), target.getPublicKeyAlgorithm());
        assertEquals(HashAlgorithm.SHA512.getAlgorithmId(), target.getHashAlgorithm());
        assertArrayEquals(hash, target.getHashData());
    }

    @Test
    public void testSetFeatures() {
        wrapper.setFeatures(Feature.MODIFICATION_DETECTION, Feature.AEAD_ENCRYPTED_DATA);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        Features features = vector.getFeatures();
        assertTrue(features.supportsModificationDetection());
        assertTrue(features.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        assertFalse(features.supportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));
    }

    @Test
    public void testSetTrust() {
        wrapper.setTrust(10, 5);
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        TrustSignature trustSignature = (TrustSignature) vector.getSubpacket(SignatureSubpacketTags.TRUST_SIG);
        assertNotNull(trustSignature);
        assertEquals(10, trustSignature.getDepth());
        assertEquals(5, trustSignature.getTrustAmount());
    }

    @Test
    public void testAddEmbeddedSignature() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        Iterator<PGPSecretKey> secretKeyIterator = secretKeys.iterator();
        PGPSecretKey primaryKey = secretKeyIterator.next();
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(primaryKey.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId())
        );

        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(primaryKey, (Passphrase) null);
        generator.init(SignatureType.DIRECT_KEY.getCode(), privateKey);
        PGPSignature sig1 = generator.generateCertification(primaryKey.getPublicKey());

        generator.init(SignatureType.DIRECT_KEY.getCode(), privateKey);
        PGPSignature sig2 = generator.generateCertification(secretKeyIterator.next().getPublicKey());

        wrapper.addEmbeddedSignature(sig1);

        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(1, vector.getEmbeddedSignatures().size());
        assertArrayEquals(sig1.getSignature(), vector.getEmbeddedSignatures().get(0).getSignature());

        wrapper.addEmbeddedSignature(sig2);

        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(2, vector.getEmbeddedSignatures().size());
        assertArrayEquals(sig2.getSignature(), vector.getEmbeddedSignatures().get(1).getSignature());

        wrapper.clearEmbeddedSignatures();
        vector = SignatureSubpacketsHelper.toVector(wrapper);
        assertEquals(0, vector.getEmbeddedSignatures().size());
    }

    @Test
    public void testExtractSubpacketsFromVector() throws IOException {
        Date sigCreationDate = DateUtil.parseUTCDate("2021-11-06 12:39:06 UTC");
        PGPPublicKeyRing publicKeys = TestKeys.getEmilPublicKeyRing();
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(publicKeys);
        long keyId = fingerprint.getKeyId();

        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
        // These are not extracted from the vector
        subpackets.setSignatureCreationTime(true, sigCreationDate);
        subpackets.setIssuerKeyID(true, keyId);
        subpackets.setIssuerFingerprint(true, publicKeys.getPublicKey());
        // These are extracted
        subpackets.setSignatureExpirationTime(true, 256000);
        subpackets.setExportable(true, true);
        subpackets.setTrust(true, 5, 15);
        subpackets.setRevocable(true, true);
        subpackets.setKeyExpirationTime(true, 512000);
        subpackets.setPreferredSymmetricAlgorithms(true, new int[] {
                SymmetricKeyAlgorithm.AES_192.getAlgorithmId(), SymmetricKeyAlgorithm.AES_128.getAlgorithmId()
        });
        subpackets.addRevocationKey(true, publicKeys.getPublicKey().getAlgorithm(),
                publicKeys.getPublicKey().getFingerprint());
        subpackets.addNotationData(false, true, "test@test.test", "test");
        subpackets.addNotationData(false,  true, "check@check.check", "check");
        subpackets.setPreferredHashAlgorithms(true, new int[] {
                HashAlgorithm.SHA512.getAlgorithmId(), HashAlgorithm.SHA384.getAlgorithmId()
        });
        subpackets.setPreferredCompressionAlgorithms(true, new int[] {
                CompressionAlgorithm.ZIP.getAlgorithmId(), CompressionAlgorithm.BZIP2.getAlgorithmId()
        });
        subpackets.setPrimaryUserID(true, true);
        subpackets.setKeyFlags(true, KeyFlag.toBitmask(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER));
        subpackets.addSignerUserID(false, "alice@test.test");
        subpackets.setRevocationReason(true, RevocationAttributes.Reason.KEY_RETIRED.code(), "Key was retired.");
        subpackets.setFeature(true, Feature.toBitmask(Feature.MODIFICATION_DETECTION, Feature.AEAD_ENCRYPTED_DATA));
        byte[] hash = new byte[128];
        new Random().nextBytes(hash);
        subpackets.setSignatureTarget(false, publicKeys.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId(), hash);
        subpackets.addIntendedRecipientFingerprint(true, publicKeys.getPublicKey());
        PreferredAlgorithms aead = new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS, false, new int[] {2});
        subpackets.addCustomSubpacket(aead);


        SignatureSubpackets wrapper = SignatureSubpackets.createSubpacketsFrom(subpackets.generate());
        PGPSignatureSubpacketVector vector = SignatureSubpacketsHelper.toVector(wrapper);

        // Verify these are not extracted
        assertEquals(0, vector.getIssuerKeyID());
        assertNull(vector.getIssuerFingerprint());
        assertNull(vector.getSignatureCreationTime());

        // Verify these are extracted
        assertEquals(256000, vector.getSignatureExpirationTime());
        assertTrue(((Exportable) vector.getSubpacket(SignatureSubpacketTags.EXPORTABLE)).isExportable());
        TrustSignature trust = (TrustSignature) vector.getSubpacket(SignatureSubpacketTags.TRUST_SIG);
        assertEquals(5, trust.getDepth());
        assertEquals(15, trust.getTrustAmount());
        assertTrue(((Revocable) vector.getSubpacket(SignatureSubpacketTags.REVOCABLE)).isRevocable());
        assertEquals(512000, vector.getKeyExpirationTime());
        assertArrayEquals(new int[] {
                SymmetricKeyAlgorithm.AES_192.getAlgorithmId(), SymmetricKeyAlgorithm.AES_128.getAlgorithmId()
        }, vector.getPreferredSymmetricAlgorithms());
        assertArrayEquals(publicKeys.getPublicKey().getFingerprint(),
                ((RevocationKey) vector.getSubpacket(SignatureSubpacketTags.REVOCATION_KEY)).getFingerprint());
        assertEquals(2, vector.getNotationDataOccurrences().length);
        assertEquals("test@test.test", vector.getNotationDataOccurrences()[0].getNotationName());
        assertEquals("test", vector.getNotationDataOccurrences()[0].getNotationValue());
        assertEquals("check@check.check", vector.getNotationDataOccurrences()[1].getNotationName());
        assertEquals("check", vector.getNotationDataOccurrences()[1].getNotationValue());
        assertArrayEquals(new int[] {
                HashAlgorithm.SHA512.getAlgorithmId(), HashAlgorithm.SHA384.getAlgorithmId()
        }, vector.getPreferredHashAlgorithms());
        assertArrayEquals(new int[] {
                CompressionAlgorithm.ZIP.getAlgorithmId(), CompressionAlgorithm.BZIP2.getAlgorithmId()
        }, vector.getPreferredCompressionAlgorithms());
        assertTrue(vector.isPrimaryUserID());
        assertEquals(KeyFlag.toBitmask(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER), vector.getKeyFlags());
        assertEquals("alice@test.test", vector.getSignerUserID());
        RevocationReason reason = (RevocationReason) vector.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON);
        assertEquals(RevocationAttributes.Reason.KEY_RETIRED.code(), reason.getRevocationReason());
        assertEquals("Key was retired.", reason.getRevocationDescription());
        assertTrue(vector.getFeatures().supportsFeature(Features.FEATURE_MODIFICATION_DETECTION));
        assertTrue(vector.getFeatures().supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        SignatureTarget signatureTarget = vector.getSignatureTarget();
        assertEquals(publicKeys.getPublicKey().getAlgorithm(), signatureTarget.getPublicKeyAlgorithm());
        assertEquals(HashAlgorithm.SHA512.getAlgorithmId(), signatureTarget.getHashAlgorithm());
        assertArrayEquals(hash, signatureTarget.getHashData());
        assertArrayEquals(publicKeys.getPublicKey().getFingerprint(), vector.getIntendedRecipientFingerprint().getFingerprint());
        PreferredAlgorithms aeadAlgorithms = (PreferredAlgorithms) vector.getSubpacket(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
        assertArrayEquals(aead.getPreferences(), aeadAlgorithms.getPreferences());
    }
}
