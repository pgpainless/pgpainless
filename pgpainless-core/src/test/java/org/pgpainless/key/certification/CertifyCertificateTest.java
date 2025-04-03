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
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.CollectionUtils;

import javax.annotation.Nonnull;

public class CertifyCertificateTest {

    @Test
    public void testUserIdCertification() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        OpenPGPKey alice = api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>");
        String bobUserId = "Bob <bob@pgpainless.org>";
        OpenPGPKey bob = api.generateKey().modernKeyRing(bobUserId);

        OpenPGPCertificate bobCertificate = bob.toCertificate();

        CertifyCertificate.CertificationResult result = api.generateCertification()
                .certifyUserId(bobUserId, bobCertificate)
                .withKey(alice, protector)
                .build();

        assertNotNull(result);
        PGPSignature signature = result.getPgpSignature();
        assertNotNull(signature);
        assertEquals(SignatureType.GENERIC_CERTIFICATION, SignatureType.requireFromCode(signature.getSignatureType()));
        assertEquals(alice.getPrimaryKey().getPGPPublicKey().getKeyID(), signature.getKeyID());

        assertTrue(result.getCertifiedCertificate().getUserId("Bob <bob@pgpainless.org>").getCertificationBy(alice).isValid());

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
        PGPainless api = PGPainless.getInstance();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        OpenPGPKey alice = api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bob = api.generateKey().modernKeyRing("Bob <bob@pgpainless.org>");

        OpenPGPCertificate bobCertificate = bob.toCertificate();

        CertifyCertificate.CertificationResult result = api.generateCertification()
                .delegateTrust(bobCertificate, Trustworthiness.fullyTrusted().introducer())
                .withKey(alice, protector)
                .build();

        assertNotNull(result);
        OpenPGPSignature signature = result.getCertification();
        PGPSignature pgpSignature = signature.getSignature();
        assertNotNull(signature);
        assertEquals(SignatureType.DIRECT_KEY, SignatureType.requireFromCode(pgpSignature.getSignatureType()));
        assertEquals(alice.getPrimaryKey().getPGPPublicKey().getKeyID(), pgpSignature.getKeyID());
        TrustSignature trustSignaturePacket = pgpSignature.getHashedSubPackets().getTrust();
        assertNotNull(trustSignaturePacket);
        Trustworthiness trustworthiness = new Trustworthiness(trustSignaturePacket.getTrustAmount(), trustSignaturePacket.getDepth());
        assertTrue(trustworthiness.isFullyTrusted());
        assertTrue(trustworthiness.isIntroducer());
        assertFalse(trustworthiness.canIntroduce(1));

        assertTrue(result.getCertifiedCertificate().getDelegationBy(alice).isValid());

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
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey aliceKey = api.generateKey()
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bobKey = api.generateKey()
                .modernKeyRing("Bob <bob@pgpainless.org>");

        OpenPGPCertificate bobCert = bobKey.toCertificate();
        String petName = "Bobby";

        CertifyCertificate.CertificationResult result = api.generateCertification()
                .certifyUserId(petName, bobCert)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(@Nonnull CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setExportable(false);
                    }
                });

        OpenPGPSignature certification = result.getCertification();
        PGPSignature signature = certification.getSignature();
        assertEquals(aliceKey.getPrimaryKey().getPGPPublicKey().getKeyID(), signature.getKeyID());
        assertEquals(CertificationType.GENERIC.asSignatureType().getCode(), signature.getSignatureType());

        OpenPGPCertificate certWithPetName = result.getCertifiedCertificate();
        KeyRingInfo info = api.inspect(certWithPetName);
        assertTrue(info.getUserIds().contains(petName));
        assertFalse(info.getValidUserIds().contains(petName));
    }

    @Test
    public void testScopedDelegation() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey aliceKey = api.generateKey()
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey caKey = api.generateKey()
                .modernKeyRing("CA <ca@example.com>");
        OpenPGPCertificate caCert = caKey.toCertificate();

        CertifyCertificate.CertificationResult result = api.generateCertification()
                .delegateTrust(caCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(@Nonnull CertificationSubpackets hashedSubpackets) {
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
