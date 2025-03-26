// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.certification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertifyV6CertificateTest {

    @Test
    public void testCertifyV6CertWithV6Key() throws PGPException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v6)
                .modernKeyRing("Bob <bob@pgpainless.org>");
        OpenPGPCertificate bobCert = bobKey.toCertificate();

        // Create a certification on Bobs certificate
        OpenPGPCertificate bobCertified = api.generateCertification()
                .userIdOnCertificate("Bob <bob@pgpainless.org>", bobCert)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // Check that there is a valid certification chain from Alice to Bobs UID
        OpenPGPCertificate.OpenPGPSignatureChain signatureChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceKey.toCertificate());
        assertNotNull(signatureChain);
        assertTrue(signatureChain.isValid());



        // Revoke Alice' key and...
        OpenPGPKey aliceRevoked = api.modify(aliceKey)
                .revoke(SecretKeyRingProtector.unprotectedKeys())
                .done();

        // ...verify we no longer have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain missingChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getCertificationBy(aliceRevoked.toCertificate());
        assertNull(missingChain);

        OpenPGPCertificate.OpenPGPSignatureChain revokedChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceRevoked);
        assertNotNull(revokedChain);
        assertTrue(revokedChain.isValid());


        // Instead, revoke the certification itself and...
        bobCertified = api.generateCertification()
                .revokeUserIdOnCertificate("Bob <bob@pgpainless.org>", bobCertified)
                .withKey(aliceKey, SecretKeyRingProtector.unprotectedKeys())
                .build().getCertifiedCertificate();

        // ...verify we now have a valid certification chain
        OpenPGPCertificate.OpenPGPSignatureChain brokenChain =
                bobCertified.getUserId("Bob <bob@pgpainless.org>")
                        .getRevocationBy(aliceKey.toCertificate());
        assertNotNull(brokenChain);
        assertTrue(brokenChain.isValid());
    }
}
