// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.algorithm.PublicKeyAlgorithm;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GenerateV6KeyTest {

    @Test
    public void generateModernV6Key() {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@example.org>")
                .getPGPSecretKeyRing();
        assertEquals(6, secretKey.getPublicKey().getVersion());
    }

    @Test
    public void buildMinimalEd25519V6Key() throws PGPException {
        OpenPGPKey key = PGPainless.getInstance().buildKey(OpenPGPKeyVersion.v6)
                .withPrimaryKey(PGPKeyPairGenerator::generateEd25519KeyPair, new SignatureParameters.Callback() {
                    @Override
                    public SignatureParameters apply(SignatureParameters parameters) {
                        return parameters.setHashedSubpacketsFunction(pgpSignatureSubpacketGenerator -> {
                            // TODO: Remove once https://github.com/bcgit/bc-java/pull/2013 lands
                            pgpSignatureSubpacketGenerator.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                            pgpSignatureSubpacketGenerator.setKeyFlags(KeyFlag.SIGN_DATA.getFlag());
                            return pgpSignatureSubpacketGenerator;
                        });
                    }
                })
                .build();

        assertTrue(key.isSecretKey());

        assertEquals(1, key.getKeys().size());
        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        assertEquals(6, primaryKey.getVersion());
        assertTrue(primaryKey.isPrimaryKey());
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(), primaryKey.getPGPPublicKey().getAlgorithm());
        assertEquals(primaryKey, key.getSigningKeys().get(0));
        assertTrue(key.getEncryptionKeys().isEmpty());

        OpenPGPKey.OpenPGPSecretKey primarySecretKey = key.getPrimarySecretKey();
        assertEquals(primarySecretKey, key.getSecretKey(primaryKey));
    }

    @Test
    public void buildCompositeCurve25519V6Key()
            throws PGPException, IOException {
        OpenPGPKey key = PGPainless.getInstance().buildKey(OpenPGPKeyVersion.v6)
                .withPrimaryKey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey(PGPKeyPairGenerator::generateX25519KeyPair)
                .addUserId("Alice <alice@pgpainless.org>")
                .build();

        assertTrue(key.isSecretKey());
        assertEquals(3, key.getKeys().size());
        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(), primaryKey.getPGPPublicKey().getAlgorithm());
        assertEquals(6, primaryKey.getVersion());
        assertTrue(primaryKey.isPrimaryKey());
        assertEquals(primaryKey, key.getKeys().get(0));

        OpenPGPCertificate.OpenPGPComponentKey signingKey = key.getKeys().get(1);
        assertTrue(key.getSigningKeys().contains(signingKey));
        assertEquals(6, signingKey.getVersion());
        assertEquals(PublicKeyAlgorithm.ED25519.getAlgorithmId(), signingKey.getPGPPublicKey().getAlgorithm());
        assertFalse(signingKey.isPrimaryKey());

        OpenPGPCertificate.OpenPGPComponentKey encryptionKey = key.getKeys().get(2);
        assertTrue(key.getEncryptionKeys().contains(encryptionKey));
        assertEquals(6, encryptionKey.getVersion());
        assertEquals(PublicKeyAlgorithm.X25519.getAlgorithmId(), encryptionKey.getPGPPublicKey().getAlgorithm());
        assertFalse(encryptionKey.isPrimaryKey());

        OpenPGPCertificate certificate = key.toCertificate();
        assertFalse(certificate.isSecretKey());

        System.out.println(certificate.toAsciiArmoredString());
    }
}
