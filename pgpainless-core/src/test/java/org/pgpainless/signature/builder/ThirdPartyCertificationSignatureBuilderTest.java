// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ThirdPartyCertificationSignatureBuilderTest {

    @Test
    public void testInvalidSignatureTypeThrows() {
        OpenPGPKey secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice");
        assertThrows(IllegalArgumentException.class, () ->
                new ThirdPartyCertificationSignatureBuilder(
                        SignatureType.BINARY_DOCUMENT, // invalid type
                        secretKeys.getPrimarySecretKey(),
                        SecretKeyRingProtector.unprotectedKeys()));
    }

    @Test
    public void testUserIdCertification() throws PGPException {
        OpenPGPKey secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice");

        OpenPGPCertificate bobsPublicKeys = PGPainless.generateKeyRing().modernKeyRing("Bob")
                .toCertificate();

        ThirdPartyCertificationSignatureBuilder signatureBuilder = new ThirdPartyCertificationSignatureBuilder(
                secretKeys.getPrimarySecretKey(),
                SecretKeyRingProtector.unprotectedKeys());

        signatureBuilder.applyCallback(new CertificationSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                hashedSubpackets.setExportable(true, false);
            }
        });

        OpenPGPSignature certification = signatureBuilder.build(bobsPublicKeys, "Bob");
        PGPSignature signature = certification.getSignature();
        assertEquals(SignatureType.GENERIC_CERTIFICATION, SignatureType.valueOf(signature.getSignatureType()));
        assertTrue(KeyIdentifier.matches(signature.getKeyIdentifiers(), secretKeys.getKeyIdentifier(), true));
        assertArrayEquals(
                secretKeys.getPrimaryKey().getPGPPublicKey().getFingerprint(),
                signature.getHashedSubPackets().getIssuerFingerprint().getFingerprint());
        Exportable exportable = SignatureSubpacketsUtil.getExportableCertification(signature);
        assertNotNull(exportable);
        assertFalse(exportable.isExportable());

        // test sig correctness
        signature.init(OpenPGPImplementation.getInstance().pgpContentVerifierBuilderProvider(),
                secretKeys.getPrimaryKey().getPGPPublicKey());
        assertTrue(signature.verifyCertification("Bob", bobsPublicKeys.getPrimaryKey().getPGPPublicKey()));
    }
}
