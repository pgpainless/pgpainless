// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.consumer.SignaturePicker;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class SignatureSubpacketsUtilTest {

    @Test
    public void testGetKeyExpirationTimeAsDate() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Expire");
        Date expiration = Date.from(new Date().toInstant().plus(365, ChronoUnit.DAYS));
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expiration, SecretKeyRingProtector.unprotectedKeys())
                .done();

        PGPSignature expirationSig = SignaturePicker.pickCurrentUserIdCertificationSignature(
                secretKeys, "Expire", Policy.getInstance(), new Date());
        PGPPublicKey notTheRightKey = PGPainless.inspectKeyRing(secretKeys).getSigningSubkeys().get(0);

        assertThrows(IllegalArgumentException.class, () ->
                SignatureSubpacketsUtil.getKeyExpirationTimeAsDate(expirationSig, notTheRightKey));
    }

    @Test
    public void testGetRevocable() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignature withoutRevocable = generator.generateCertification(secretKeys.getPublicKey());
        assertNull(SignatureSubpacketsUtil.getRevocable(withoutRevocable));

        generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setRevocable(true, true);
        generator.setHashedSubpackets(hashed.generate());
        PGPSignature withRevocable = generator.generateCertification(secretKeys.getPublicKey());
        assertNotNull(SignatureSubpacketsUtil.getRevocable(withRevocable));
    }

    @Test
    public void testParsePreferredCompressionAlgorithms() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        Set<CompressionAlgorithm> compressionAlgorithmSet = new LinkedHashSet<>(Arrays.asList(CompressionAlgorithm.BZIP2, CompressionAlgorithm.ZIP));
        int[] ids = new int[compressionAlgorithmSet.size()];
        Iterator<CompressionAlgorithm> it = compressionAlgorithmSet.iterator();
        for (int i = 0; i < ids.length; i++) {
            ids[i] = it.next().getAlgorithmId();
        }
        hashed.setPreferredCompressionAlgorithms(true, ids);
        generator.setHashedSubpackets(hashed.generate());

        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());

        Set<CompressionAlgorithm> parsed = SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(signature);
        assertEquals(compressionAlgorithmSet, parsed);
    }

    @Test
    public void testParseKeyFlagsOfNullIsNull() {
        assertNull(SignatureSubpacketsUtil.parseKeyFlags(null));
    }

    @Test
    public void testParseKeyFlagsOfNullSubpacketIsNull() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignature withoutKeyFlags = generator.generateCertification(secretKeys.getPublicKey());
        assertNull(SignatureSubpacketsUtil.parseKeyFlags(withoutKeyFlags));
    }

    @Test
    public void testParseFeaturesIsNullForNullSubpacket() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignature withoutKeyFlags = generator.generateCertification(secretKeys.getPublicKey());
        assertNull(SignatureSubpacketsUtil.parseFeatures(withoutKeyFlags));
    }

    @Test
    public void testParseFeatures() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setFeature(true, Feature.toBitmask(Feature.MODIFICATION_DETECTION, Feature.AEAD_ENCRYPTED_DATA));
        generator.setHashedSubpackets(hashed.generate());

        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());
        Set<Feature> featureSet = SignatureSubpacketsUtil.parseFeatures(signature);
        assertNotNull(featureSet);
        assertEquals(2, featureSet.size());
        assertTrue(featureSet.contains(Feature.MODIFICATION_DETECTION));
        assertTrue(featureSet.contains(Feature.AEAD_ENCRYPTED_DATA));
        assertFalse(featureSet.contains(Feature.VERSION_5_PUBLIC_KEY));
    }

    @Test
    public void getSignatureTargetIsNull() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignature withoutSignatureTarget = generator.generateCertification(secretKeys.getPublicKey());

        assertNull(SignatureSubpacketsUtil.getSignatureTarget(withoutSignatureTarget));
    }

    @Test
    public void testGetUnhashedNotationData() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator unhashed = new PGPSignatureSubpacketGenerator();
        unhashed.addNotationData(true, true, "test@notation.data", "notation-value");
        unhashed.addNotationData(true, true, "test@notation.data", "another-value");
        unhashed.addNotationData(true, true, "another@notation.data", "Hello-World!");
        generator.setUnhashedSubpackets(unhashed.generate());

        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());
        List<NotationData> notations = SignatureSubpacketsUtil.getUnhashedNotationData(signature);
        assertEquals(3, notations.size());
        assertEquals("test@notation.data", notations.get(0).getNotationName());
        assertEquals("test@notation.data", notations.get(1).getNotationName());
        assertEquals("another@notation.data", notations.get(2).getNotationName());
        assertEquals("notation-value", notations.get(0).getNotationValue());
        assertEquals("another-value", notations.get(1).getNotationValue());
        assertEquals("Hello-World!", notations.get(2).getNotationValue());

        notations = SignatureSubpacketsUtil.getUnhashedNotationData(signature, "test@notation.data");
        assertEquals(2, notations.size());
        assertEquals("notation-value", notations.get(0).getNotationValue());
        assertEquals("another-value", notations.get(1).getNotationValue());

        notations = SignatureSubpacketsUtil.getUnhashedNotationData(signature, "invalid");
        assertEquals(0, notations.size());
    }

    @Test
    public void testGetRevocationKeyIsNull() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());

        assertNull(SignatureSubpacketsUtil.getRevocationKey(signature));
    }

    @Test
    public void testGetRevocationKey() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.addRevocationKey(true, secretKeys.getPublicKey().getAlgorithm(), secretKeys.getPublicKey().getFingerprint());
        generator.setHashedSubpackets(hashed.generate());
        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());

        RevocationKey revocationKey = SignatureSubpacketsUtil.getRevocationKey(signature);
        assertNotNull(revocationKey);
        assertArrayEquals(secretKeys.getPublicKey().getFingerprint(), revocationKey.getFingerprint());
        assertEquals(secretKeys.getPublicKey().getAlgorithm(), revocationKey.getAlgorithm());
    }

    @Test
    public void testGetIntendedRecipientFingerprintsEmpty() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());

        assertEquals(0, SignatureSubpacketsUtil.getIntendedRecipientFingerprints(signature).size());
    }

    @Test
    public void testGetIntendedRecipientFingerprints() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.addIntendedRecipientFingerprint(true, secretKeys.getPublicKey());
        hashed.addIntendedRecipientFingerprint(true, TestKeys.getCryptiePublicKeyRing().getPublicKey());
        generator.setHashedSubpackets(hashed.generate());
        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());

        List<IntendedRecipientFingerprint> intendedRecipientFingerprints = SignatureSubpacketsUtil.getIntendedRecipientFingerprints(signature);
        assertEquals(2, intendedRecipientFingerprints.size());
        assertArrayEquals(secretKeys.getPublicKey().getFingerprint(), intendedRecipientFingerprints.get(0).getFingerprint());
        assertArrayEquals(TestKeys.getCryptiePublicKeyRing().getPublicKey().getFingerprint(), intendedRecipientFingerprints.get(1).getFingerprint());
    }

    @Test
    public void testGetExportableCertification() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setExportable(true, true);
        generator.setHashedSubpackets(hashed.generate());

        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());
        Exportable exportable = SignatureSubpacketsUtil.getExportableCertification(signature);
        assertNotNull(exportable);
        assertTrue(exportable.isExportable());
    }

    @Test
    public void testGetTrustSignature() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPrivateKey certKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = getSignatureGenerator(certKey, SignatureType.CASUAL_CERTIFICATION);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setTrust(true, 10, 3);
        generator.setHashedSubpackets(hashed.generate());

        PGPSignature signature = generator.generateCertification(secretKeys.getPublicKey());
        TrustSignature trustSignature = SignatureSubpacketsUtil.getTrustSignature(signature);
        assertNotNull(trustSignature);
        assertEquals(10, trustSignature.getDepth());
        assertEquals(3, trustSignature.getTrustAmount());
    }

    private PGPSignatureGenerator getSignatureGenerator(PGPPrivateKey signingKey,
                                        SignatureType signatureType) throws PGPException {
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        signingKey.getPublicKeyPacket().getAlgorithm(),
                        HashAlgorithm.SHA512.getAlgorithmId()));
        signatureGenerator.init(signatureType.getCode(), signingKey);
        return signatureGenerator;
    }
}
