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
package org.pgpainless.signature;

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
import java.util.Set;

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
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class SignatureSubpacketsUtilTest {

    @Test
    public void test() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Expire", null);
        Date expiration = Date.from(new Date().toInstant().plus(365, ChronoUnit.DAYS));
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expiration, SecretKeyRingProtector.unprotectedKeys())
                .done();

        PGPSignature expirationSig = SignaturePicker.pickCurrentUserIdCertificationSignature(secretKeys, "Expire", Policy.getInstance(), new Date());
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
        assertEquals(2, featureSet.size());
        assertTrue(featureSet.contains(Feature.MODIFICATION_DETECTION));
        assertTrue(featureSet.contains(Feature.AEAD_ENCRYPTED_DATA));
        assertFalse(featureSet.contains(Feature.VERSION_5_PUBLIC_KEY));
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
