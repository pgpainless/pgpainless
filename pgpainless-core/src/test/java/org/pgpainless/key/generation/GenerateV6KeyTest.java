// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.KeyRingProtectionSettings;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GenerateV6KeyTest {

    @Test
    public void generateModernV6Key() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@example.org>");
        assertEquals(3, key.getKeys().size());

        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        assertEquals(primaryKey, key.getCertificationKeys().get(0));
        assertEquals(6, primaryKey.getVersion());
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(),
                primaryKey.getAlgorithm());

        OpenPGPCertificate.OpenPGPComponentKey signingKey = key.getSigningKeys().get(0);
        assertEquals(6, signingKey.getVersion());
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(),
                signingKey.getAlgorithm());

        OpenPGPCertificate.OpenPGPComponentKey encryptionKey = key.getEncryptionKeys().get(0);
        assertEquals(6, encryptionKey.getVersion());
        assertEquals(PublicKeyAlgorithm.X25519.getAlgorithmId(),
                encryptionKey.getAlgorithm());
    }

    @Test
    public void buildMinimalEd25519V6Key() throws PGPException {
        OpenPGPKey key = PGPainless.getInstance()._buildKey(OpenPGPKeyVersion.v6)
                .withPrimaryKey(PGPKeyPairGenerator::generateEd25519KeyPair, new SignatureParameters.Callback() {
                    @Override
                    public SignatureParameters apply(SignatureParameters parameters) {
                        return parameters.setHashedSubpacketsFunction(pgpSignatureSubpacketGenerator -> {
                            pgpSignatureSubpacketGenerator.setKeyFlags(KeyFlag.SIGN_DATA.getFlag());
                            return pgpSignatureSubpacketGenerator;
                        });
                    }
                })
                .build();

        assertTrue(key.isSecretKey());

        assertEquals(1, key.getKeys().size());
        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        assertTrue(key.getCertificationKeys().isEmpty());
        assertEquals(6, primaryKey.getVersion());
        assertTrue(primaryKey.isPrimaryKey());
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(),
                primaryKey.getAlgorithm());
        assertEquals(primaryKey, key.getSigningKeys().get(0));
        assertTrue(key.getEncryptionKeys().isEmpty());

        OpenPGPKey.OpenPGPSecretKey primarySecretKey = key.getPrimarySecretKey();
        assertEquals(primarySecretKey, key.getSecretKey(primaryKey));
    }

    @Test
    public void buildCompositeCurve25519V6Key()
            throws PGPException, IOException {
        OpenPGPKey key = PGPainless.getInstance()._buildKey(OpenPGPKeyVersion.v6)
                .withPrimaryKey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey(PGPKeyPairGenerator::generateX25519KeyPair)
                .addUserId("Alice <alice@pgpainless.org>")
                .build();

        assertTrue(key.isSecretKey());
        assertEquals(3, key.getKeys().size());
        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        assertEquals(primaryKey, key.getCertificationKeys().get(0));
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(), primaryKey.getAlgorithm());
        assertEquals(6, primaryKey.getVersion());
        assertTrue(primaryKey.isPrimaryKey());
        assertEquals(primaryKey, key.getKeys().get(0));

        OpenPGPCertificate.OpenPGPComponentKey signingKey = key.getKeys().get(1);
        assertTrue(key.getSigningKeys().contains(signingKey));
        assertEquals(6, signingKey.getVersion());
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(), signingKey.getAlgorithm());
        assertFalse(signingKey.isPrimaryKey());

        OpenPGPCertificate.OpenPGPComponentKey encryptionKey = key.getKeys().get(2);
        assertTrue(key.getEncryptionKeys().contains(encryptionKey));
        assertEquals(6, encryptionKey.getVersion());
        assertEquals(PublicKeyAlgorithm.X25519.getAlgorithmId(), encryptionKey.getAlgorithm());
        assertFalse(encryptionKey.isPrimaryKey());

        OpenPGPCertificate certificate = key.toCertificate();
        assertFalse(certificate.isSecretKey());

        // CHECKSTYLE:OFF
        System.out.println(certificate.toAsciiArmoredString());
        // CHECKSTYLE:ON
    }

    @Test
    public void buildMonolithicRSAKey() {
        OpenPGPKey key = PGPainless.getInstance().generateKey(OpenPGPKeyVersion.v6)
                .simpleRsaKeyRing("Alice <alice@example.org>", RsaLength._4096);

        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        // Primary key is used for all purposes
        assertEquals(primaryKey, key.getCertificationKeys().get(0));
        assertEquals(primaryKey, key.getSigningKeys().get(0));
        assertEquals(primaryKey, key.getEncryptionKeys().get(0));
    }

    @Test
    public void generateAEADProtectedModernKey()
            throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();

        // Change Policy to use AEAD for secret key protection
        api = new PGPainless(api.getAlgorithmPolicy().copy()
                .withKeyProtectionSettings(KeyRingProtectionSettings.aead()).build());

        OpenPGPKey key = api
                .generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@example.com>", "p455w0rd");

        String armored = key.toAsciiArmoredString();

        OpenPGPKey parsed = api.readKey().parseKey(armored);

        OpenPGPKey.OpenPGPSecretKey primaryKey = key.getPrimarySecretKey();
        assertEquals(SecretKeyPacket.USAGE_AEAD, primaryKey.getPGPSecretKey().getS2KUsage());

        OpenPGPKey.OpenPGPPrivateKey privateKey = primaryKey.unlock("p455w0rd".toCharArray());
        assertNotNull(privateKey);

        assertEquals(armored, parsed.toAsciiArmoredString());
    }

    @Test
    public void generateKeyOverrideFeatures() {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey key = api.buildKey(OpenPGPKeyVersion.v6)
                .setPrimaryKey(KeySpec.getBuilder(KeyType.Ed25519(), KeyFlag.CERTIFY_OTHER)
                        .overrideFeatures(Feature.MODIFICATION_DETECTION, Feature.MODIFICATION_DETECTION_2))
                .build();

        assertTrue(key.getPrimaryKey().getFeatures().supportsModificationDetection());
        assertTrue(key.getPrimaryKey().getFeatures().supportsSEIPDv2());
    }
}
