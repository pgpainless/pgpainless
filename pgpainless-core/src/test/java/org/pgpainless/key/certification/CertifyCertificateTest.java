// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.certification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.Trustworthiness;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.consumer.SignatureVerifier;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.util.DateUtil;

public class CertifyCertificateTest {

    @Test
    public void testUserIdCertification() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        String bobUserId = "Bob <bob@pgpainless.org>";
        PGPSecretKeyRing bob = PGPainless.generateKeyRing().modernKeyRing(bobUserId);

        PGPPublicKeyRing bobCertificate = PGPainless.extractCertificate(bob);

        CertifyCertificate.CertificationResult result = PGPainless.certify()
                .userIdOnCertificate(bobUserId, bobCertificate)
                .withKey(alice, protector)
                .build();

        assertNotNull(result);
        PGPSignature signature = result.getCertification();
        assertNotNull(signature);
        assertEquals(SignatureType.GENERIC_CERTIFICATION, SignatureType.valueOf(signature.getSignatureType()));
        assertEquals(alice.getPublicKey().getKeyID(), signature.getKeyID());

        assertTrue(SignatureVerifier.verifyUserIdCertification(
                bobUserId, signature, alice.getPublicKey(), bob.getPublicKey(), PGPainless.getPolicy(), DateUtil.now()));

        PGPPublicKeyRing bobCertified = result.getCertifiedCertificate();
        PGPPublicKey bobCertifiedKey = bobCertified.getPublicKey();
        // There are 2 sigs now, bobs own and alice'
        assertEquals(2, CollectionUtils.iteratorToList(bobCertifiedKey.getSignaturesForID(bobUserId)).size());
        List<PGPSignature> sigsByAlice = CollectionUtils.iteratorToList(
                bobCertifiedKey.getSignaturesForKeyID(alice.getPublicKey().getKeyID()));
        assertEquals(1, sigsByAlice.size());
        assertEquals(signature, sigsByAlice.get(0));

        assertFalse(Arrays.areEqual(bobCertificate.getEncoded(), bobCertified.getEncoded()));
    }

    @Test
    public void testKeyDelegation() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        PGPSecretKeyRing bob = PGPainless.generateKeyRing().modernKeyRing("Bob <bob@pgpainless.org>");

        PGPPublicKeyRing bobCertificate = PGPainless.extractCertificate(bob);

        CertifyCertificate.CertificationResult result = PGPainless.certify()
                .certificate(bobCertificate, Trustworthiness.fullyTrusted().introducer())
                .withKey(alice, protector)
                .build();

        assertNotNull(result);
        PGPSignature signature = result.getCertification();
        assertNotNull(signature);
        assertEquals(SignatureType.DIRECT_KEY, SignatureType.valueOf(signature.getSignatureType()));
        assertEquals(alice.getPublicKey().getKeyID(), signature.getKeyID());
        TrustSignature trustSignaturePacket = signature.getHashedSubPackets().getTrust();
        assertNotNull(trustSignaturePacket);
        Trustworthiness trustworthiness = new Trustworthiness(trustSignaturePacket.getTrustAmount(), trustSignaturePacket.getDepth());
        assertTrue(trustworthiness.isFullyTrusted());
        assertTrue(trustworthiness.isIntroducer());
        assertFalse(trustworthiness.canIntroduce(1));

        assertTrue(SignatureVerifier.verifyDirectKeySignature(
                signature, alice.getPublicKey(), bob.getPublicKey(), PGPainless.getPolicy(), DateUtil.now()));

        PGPPublicKeyRing bobCertified = result.getCertifiedCertificate();
        PGPPublicKey bobCertifiedKey = bobCertified.getPublicKey();

        List<PGPSignature> sigsByAlice = CollectionUtils.iteratorToList(
                bobCertifiedKey.getSignaturesForKeyID(alice.getPublicKey().getKeyID()));
        assertEquals(1, sigsByAlice.size());
        assertEquals(signature, sigsByAlice.get(0));

        assertFalse(Arrays.areEqual(bobCertificate.getEncoded(), bobCertified.getEncoded()));
    }
}
