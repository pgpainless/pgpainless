// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.certification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CertificationType;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.Trustworthiness;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.consumer.SignatureVerifier;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.util.DateUtil;

public class CertifyCertificateTest {

    @Test
    public void testUserIdCertification() throws PGPException, IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        OpenPGPKey alice = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        String bobUserId = "Bob <bob@pgpainless.org>";
        OpenPGPKey bob = PGPainless.generateKeyRing().modernKeyRing(bobUserId);

        OpenPGPCertificate bobCertificate = bob.toCertificate();

        CertifyCertificate.CertificationResult result = PGPainless.certify()
                .userIdOnCertificate(bobUserId, bobCertificate)
                .withKey(alice, protector)
                .build();

        assertNotNull(result);
        PGPSignature signature = result.getPgpSignature();
        assertNotNull(signature);
        assertEquals(SignatureType.GENERIC_CERTIFICATION, SignatureType.valueOf(signature.getSignatureType()));
        assertEquals(alice.getPrimaryKey().getPGPPublicKey().getKeyID(), signature.getKeyID());

        assertTrue(SignatureVerifier.verifyUserIdCertification(
                bobUserId, signature, alice.getPrimaryKey().getPGPPublicKey(), bob.getPrimaryKey().getPGPPublicKey(), PGPainless.getPolicy(), DateUtil.now()));

        OpenPGPCertificate bobCertified = result.getCertifiedCertificate();
        PGPPublicKey bobCertifiedKey = bobCertified.getPrimaryKey().getPGPPublicKey();
        // There are 2 sigs now, bobs own and alice'
        assertEquals(2, CollectionUtils.iteratorToList(bobCertifiedKey.getSignaturesForID(bobUserId)).size());
        List<PGPSignature> sigsByAlice = CollectionUtils.iteratorToList(
                bobCertifiedKey.getSignaturesForKeyID(alice.getPrimaryKey().getPGPPublicKey().getKeyID()));
        assertEquals(1, sigsByAlice.size());
        assertEquals(signature, sigsByAlice.get(0));

        assertFalse(Arrays.areEqual(bobCertificate.getPGPPublicKeyRing().getEncoded(), bobCertified.getPGPPublicKeyRing().getEncoded()));
    }

    @Test
    public void testKeyDelegation() throws PGPException, IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        OpenPGPKey alice = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bob = PGPainless.generateKeyRing().modernKeyRing("Bob <bob@pgpainless.org>");

        OpenPGPCertificate bobCertificate = bob.toCertificate();

        CertifyCertificate.CertificationResult result = PGPainless.certify()
                .certificate(bobCertificate, Trustworthiness.fullyTrusted().introducer())
                .withKey(alice, protector)
                .build();

        assertNotNull(result);
        OpenPGPSignature signature = result.getCertification();
        PGPSignature pgpSignature = signature.getSignature();
        assertNotNull(signature);
        assertEquals(SignatureType.DIRECT_KEY, SignatureType.valueOf(pgpSignature.getSignatureType()));
        assertEquals(alice.getPrimaryKey().getPGPPublicKey().getKeyID(), pgpSignature.getKeyID());
        TrustSignature trustSignaturePacket = pgpSignature.getHashedSubPackets().getTrust();
        assertNotNull(trustSignaturePacket);
        Trustworthiness trustworthiness = new Trustworthiness(trustSignaturePacket.getTrustAmount(), trustSignaturePacket.getDepth());
        assertTrue(trustworthiness.isFullyTrusted());
        assertTrue(trustworthiness.isIntroducer());
        assertFalse(trustworthiness.canIntroduce(1));

        assertTrue(SignatureVerifier.verifyDirectKeySignature(
                pgpSignature, alice.getPrimaryKey().getPGPPublicKey(), bob.getPrimaryKey().getPGPPublicKey(), PGPainless.getPolicy(), DateUtil.now()));

        OpenPGPCertificate bobCertified = result.getCertifiedCertificate();
        PGPPublicKey bobCertifiedKey = bobCertified.getPrimaryKey().getPGPPublicKey();

        List<PGPSignature> sigsByAlice = CollectionUtils.iteratorToList(
                bobCertifiedKey.getSignaturesForKeyID(alice.getPrimaryKey().getPGPPublicKey().getKeyID()));
        assertEquals(1, sigsByAlice.size());
        assertEquals(signature.getSignature(), sigsByAlice.get(0));

        assertFalse(Arrays.areEqual(bobCertificate.getPGPPublicKeyRing().getEncoded(), bobCertified.getPGPPublicKeyRing().getEncoded()));
    }

    @Test
    public void testPetNameCertification() {
        OpenPGPKey aliceKey = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bobKey = PGPainless.generateKeyRing()
                .modernKeyRing("Bob <bob@pgpainless.org>");

        OpenPGPCertificate bobCert = bobKey.toCertificate();
        String petName = "Bobby";

        CertifyCertificate.CertificationResult result = PGPainless.certify()
                .userIdOnCertificate(petName, bobCert)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setExportable(false);
                    }
                });

        OpenPGPSignature certification = result.getCertification();
        PGPSignature signature = certification.getSignature();
        assertEquals(aliceKey.getPrimaryKey().getPGPPublicKey().getKeyID(), signature.getKeyID());
        assertEquals(CertificationType.GENERIC.asSignatureType().getCode(), signature.getSignatureType());

        OpenPGPCertificate certWithPetName = result.getCertifiedCertificate();
        KeyRingInfo info = PGPainless.inspectKeyRing(certWithPetName);
        assertTrue(info.getUserIds().contains(petName));
        assertFalse(info.getValidUserIds().contains(petName));
    }

    @Test
    public void testScopedDelegation() {
        OpenPGPKey aliceKey = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey caKey = PGPainless.generateKeyRing()
                .modernKeyRing("CA <ca@example.com>");
        OpenPGPCertificate caCert = caKey.toCertificate();

        CertifyCertificate.CertificationResult result = PGPainless.certify()
                .certificate(caCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression("^.*<.+@example.com>.*$");
                    }
                });

        OpenPGPSignature certification = result.getCertification();
        PGPSignature signature = certification.getSignature();
        assertEquals(SignatureType.DIRECT_KEY.getCode(), signature.getSignatureType());
        assertEquals("^.*<.+@example.com>.*$",
                signature.getHashedSubPackets().getRegularExpression().getRegex());
    }
}
