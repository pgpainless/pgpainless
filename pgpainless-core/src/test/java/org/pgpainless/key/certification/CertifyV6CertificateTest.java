// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.certification;

import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CertificationType;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertifyV6CertificateTest {

    @Test
    public void testCertifyV6UIDWithV6Key() throws PGPException {
        // Alice (6) certifies Bob (6)
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Create a certification on Bobs certificate
        OpenPGPCertificate bobCertified = api.generateCertification()
                .certifyUserId("Bob <bob@pgpainless.org>", bobCert, CertificationType.POSITIVE)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that there is a valid certification chain from Alice to Bobs UID
        OpenPGPCertificate.OpenPGPSignatureChain certification =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceKey.toCertificate());
        assertNotNull(certification);
        assertTrue(certification.isValid());
        OpenPGPSignature certificationSignature = certification.getSignature();
        assertEquals(SignaturePacket.VERSION_6, certificationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.POSITIVE_CERTIFICATION, certificationSignature.getSignature().getSignatureType());


        // Revoke Alice' key and...
        OpenPGPKey aliceRevoked = api.modify(aliceKey)
                .revoke(SecretKeyRingProtector.unprotectedKeys())
                .done();

        // ...verify we no longer have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain missingChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceRevoked.toCertificate());
        assertNull(missingChain);

        // ...but DO have a revocation chain
        OpenPGPCertificate.OpenPGPSignatureChain revokedChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceRevoked);
        assertNotNull(revokedChain);
        assertTrue(revokedChain.isValid());
        OpenPGPSignature revocationSignature = revokedChain.getRevocation();
        assertEquals(SignaturePacket.VERSION_6, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.KEY_REVOCATION, revocationSignature.getSignature().getSignatureType());


        // Instead, revoke the certification itself and...
        bobCertified = api.generateCertification()
                .revokeCertifiedUserId("Bob <bob@pgpainless.org>", bobCertified)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // ...verify we now have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain brokenChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceKey.toCertificate());
        assertNotNull(brokenChain);
        assertTrue(brokenChain.isValid());
        revocationSignature = brokenChain.getSignature();
        assertEquals(SignaturePacket.VERSION_6, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.CERTIFICATION_REVOCATION, revocationSignature.getSignature().getSignatureType());
    }

    @Test
    public void testDelegateV6CertWithV6Key() throws PGPSignatureException {
        // Alice (6) delegates Bob (6)
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Alice delegates trust to Bob
        OpenPGPCertificate bobDelegated = api.generateCertification()
                .delegateTrust(bobCert)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that Bob is actually delegated to by Alice
        OpenPGPCertificate.OpenPGPSignatureChain delegation = bobDelegated.getDelegationBy(aliceKey.toCertificate());
        assertNotNull(delegation);
        assertTrue(delegation.isValid());
        OpenPGPSignature delegationSignature = delegation.getSignature();
        assertEquals(SignaturePacket.VERSION_6, delegationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.DIRECT_KEY, delegationSignature.getSignature().getSignatureType());

        // Alice revokes the delegation
        OpenPGPCertificate bobRevoked = api.generateCertification()
                .revokeDelegatedTrust(bobDelegated)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        OpenPGPCertificate.OpenPGPSignatureChain revocation = bobRevoked.getRevocationBy(aliceKey.toCertificate());
        assertNotNull(revocation);
        assertTrue(revocation.isValid());
        OpenPGPSignature revocationSignature = revocation.getSignature();
        assertEquals(SignaturePacket.VERSION_6, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.KEY_REVOCATION, revocationSignature.getSignature().getSignatureType());
    }

    @Test
    public void testCertifyV4UIDWithV6Key() throws PGPException {
        // Alice (6) certifies Bob (4)
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v4)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Create a certification on Bobs certificate
        // Alice => "Bob" (Bob)
        OpenPGPCertificate bobCertified = api.generateCertification()
                .certifyUserId("Bob <bob@pgpainless.org>", bobCert, CertificationType.CASUAL)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that there is a valid certification chain from Alice to Bobs UID
        OpenPGPCertificate.OpenPGPSignatureChain signatureChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceKey.toCertificate());
        assertNotNull(signatureChain);
        assertTrue(signatureChain.isValid());
        OpenPGPSignature certificationSignature = signatureChain.getSignature();
        assertEquals(SignaturePacket.VERSION_6, certificationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.CASUAL_CERTIFICATION, certificationSignature.getSignature().getSignatureType());

        // Revoke Alice' key and...
        OpenPGPKey aliceRevoked = api.modify(aliceKey)
                .revoke(SecretKeyRingProtector.unprotectedKeys())
                .done();

        // ...verify we no longer have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain missingChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceRevoked.toCertificate());
        assertNull(missingChain);


        // ...but DO have a revocation chain
        OpenPGPCertificate.OpenPGPSignatureChain revokedChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceRevoked);
        assertNotNull(revokedChain);
        assertTrue(revokedChain.isValid());
        OpenPGPSignature revocationSignature = revokedChain.getRevocation();
        assertEquals(SignaturePacket.VERSION_6, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.KEY_REVOCATION, revocationSignature.getSignature().getSignatureType());


        // Instead, revoke the certification itself and...
        bobCertified = api.generateCertification()
                .revokeCertifiedUserId("Bob <bob@pgpainless.org>", bobCertified)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // ...verify we now have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain brokenChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceKey.toCertificate());
        assertNotNull(brokenChain);
        assertTrue(brokenChain.isValid());
        revocationSignature = brokenChain.getSignature();
        assertEquals(SignaturePacket.VERSION_6, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.CERTIFICATION_REVOCATION, revocationSignature.getSignature().getSignatureType());
    }

    @Test
    public void testDelegateV4CertWithV6Key() throws PGPSignatureException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Alice delegates trust to Bob
        OpenPGPCertificate bobDelegated = api.generateCertification()
                .delegateTrust(bobCert)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that Bob is actually delegated to by Alice
        OpenPGPCertificate.OpenPGPSignatureChain delegation = bobDelegated.getDelegationBy(aliceKey.toCertificate());
        assertNotNull(delegation);
        assertTrue(delegation.isValid());
        OpenPGPSignature delegationSignature = delegation.getSignature();
        assertEquals(SignaturePacket.VERSION_6, delegationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.DIRECT_KEY, delegationSignature.getSignature().getSignatureType());

        // Alice revokes the delegation
        OpenPGPCertificate bobRevoked = api.generateCertification()
                .revokeDelegatedTrust(bobDelegated)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        OpenPGPCertificate.OpenPGPSignatureChain revocation = bobRevoked.getRevocationBy(aliceKey.toCertificate());
        assertNotNull(revocation);
        assertTrue(revocation.isValid());
        OpenPGPSignature revocationSignature = revocation.getSignature();
        assertEquals(SignaturePacket.VERSION_6, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.KEY_REVOCATION, revocationSignature.getSignature().getSignatureType());
    }

    @Test
    public void testCertifyV6UIDWithV4Key() throws PGPException {
        // Alice (4) certifies Bob (6)
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v4)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Create a certification on Bobs certificate
        // Alice => "Bob" (Bob)
        OpenPGPCertificate bobCertified = api.generateCertification()
                .certifyUserId("Bob <bob@pgpainless.org>", bobCert, CertificationType.CASUAL)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that there is a valid certification chain from Alice to Bobs UID
        OpenPGPCertificate.OpenPGPSignatureChain signatureChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceKey.toCertificate());
        assertNotNull(signatureChain);
        assertTrue(signatureChain.isValid());
        OpenPGPSignature certificationSignature = signatureChain.getSignature();
        assertEquals(SignaturePacket.VERSION_4, certificationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.CASUAL_CERTIFICATION, certificationSignature.getSignature().getSignatureType());

        // Revoke Alice' key and...
        OpenPGPKey aliceRevoked = api.modify(aliceKey)
                .revoke(SecretKeyRingProtector.unprotectedKeys())
                .done();

        // ...verify we no longer have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain missingChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceRevoked.toCertificate());
        assertNull(missingChain);


        // ...but DO have a revocation chain
        OpenPGPCertificate.OpenPGPSignatureChain revokedChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceRevoked);
        assertNotNull(revokedChain);
        assertTrue(revokedChain.isValid());
        OpenPGPSignature revocationSignature = revokedChain.getRevocation();
        assertEquals(SignaturePacket.VERSION_4, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.KEY_REVOCATION, revocationSignature.getSignature().getSignatureType());


        // Instead, revoke the certification itself and...
        bobCertified = api.generateCertification()
                .revokeCertifiedUserId("Bob <bob@pgpainless.org>", bobCertified)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // ...verify we now have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain brokenChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceKey.toCertificate());
        assertNotNull(brokenChain);
        assertTrue(brokenChain.isValid());
        revocationSignature = brokenChain.getSignature();
        assertEquals(SignaturePacket.VERSION_4, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.CERTIFICATION_REVOCATION, revocationSignature.getSignature().getSignatureType());
    }

    @Test
    public void testDelegateV6CertWithV4Key() throws PGPSignatureException {
        // Alice (4) delegates Bob (6)
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v4)
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Alice delegates trust to Bob
        OpenPGPCertificate bobDelegated = api.generateCertification()
                .delegateTrust(bobCert)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that Bob is actually delegated to by Alice
        OpenPGPCertificate.OpenPGPSignatureChain delegation = bobDelegated.getDelegationBy(aliceKey.toCertificate());
        assertNotNull(delegation);
        assertTrue(delegation.isValid());
        OpenPGPSignature delegationSignature = delegation.getSignature();
        assertEquals(SignaturePacket.VERSION_4, delegationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.DIRECT_KEY, delegationSignature.getSignature().getSignatureType());

        // Alice revokes the delegation
        OpenPGPCertificate bobRevoked = api.generateCertification()
                .revokeDelegatedTrust(bobDelegated)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        OpenPGPCertificate.OpenPGPSignatureChain revocation = bobRevoked.getRevocationBy(aliceKey.toCertificate());
        assertNotNull(revocation);
        assertTrue(revocation.isValid());
        OpenPGPSignature revocationSignature = revocation.getSignature();
        assertEquals(SignaturePacket.VERSION_4, revocationSignature.getSignature().getVersion());
        assertEquals(PGPSignature.KEY_REVOCATION, revocationSignature.getSignature().getSignatureType());
    }
}
