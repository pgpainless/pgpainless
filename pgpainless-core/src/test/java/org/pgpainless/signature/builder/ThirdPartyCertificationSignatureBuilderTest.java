// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ThirdPartyCertificationSignatureBuilderTest {

    @Test
    public void testInvalidSignatureTypeThrows() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice");
        assertThrows(IllegalArgumentException.class, () ->
                new ThirdPartyCertificationSignatureBuilder(
                        SignatureType.BINARY_DOCUMENT, // invalid type
                        secretKeys.getSecretKey(),
                        SecretKeyRingProtector.unprotectedKeys()));
    }

    @Test
    public void testUserIdCertification() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice");

        PGPPublicKeyRing bobsPublicKeys = PGPainless.extractCertificate(
                PGPainless.generateKeyRing().modernKeyRing("Bob"));

        ThirdPartyCertificationSignatureBuilder signatureBuilder = new ThirdPartyCertificationSignatureBuilder(
                secretKeys.getSecretKey(),
                SecretKeyRingProtector.unprotectedKeys());

        signatureBuilder.applyCallback(new CertificationSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                hashedSubpackets.setExportable(true, false);
            }
        });

        PGPSignature certification = signatureBuilder.build(bobsPublicKeys, "Bob");
        assertEquals(SignatureType.GENERIC_CERTIFICATION, SignatureType.valueOf(certification.getSignatureType()));
        assertEquals(secretKeys.getPublicKey().getKeyID(), certification.getKeyID());
        assertArrayEquals(secretKeys.getPublicKey().getFingerprint(), certification.getHashedSubPackets().getIssuerFingerprint().getFingerprint());
        Exportable exportable = SignatureSubpacketsUtil.getExportableCertification(certification);
        assertNotNull(exportable);
        assertFalse(exportable.isExportable());

        // test sig correctness
        certification.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), secretKeys.getPublicKey());
        assertTrue(certification.verifyCertification("Bob", bobsPublicKeys.getPublicKey()));
    }
}
