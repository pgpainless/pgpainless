// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.util.CollectionUtils;

public class RevocationCertificateTest {

    @Test
    public void createRevocationCertificateTest() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();

        PGPSignature revocation = PGPainless.modifyKeyRing(secretKeys)
                .createRevocation(SecretKeyRingProtector.unprotectedKeys(),
                        RevocationAttributes.createKeyRevocation()
                                .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                                .withoutDescription());

        assertNotNull(revocation);

        assertTrue(PGPainless.inspectKeyRing(secretKeys).isKeyValidlyBound(secretKeys.getPublicKey().getKeyID()));

        // merge key and revocation certificate
        PGPSecretKeyRing revokedKey = KeyRingUtils.keysPlusSecretKey(
                secretKeys,
                KeyRingUtils.secretKeyPlusSignature(secretKeys.getSecretKey(), revocation));

        assertFalse(PGPainless.inspectKeyRing(revokedKey).isKeyValidlyBound(secretKeys.getPublicKey().getKeyID()));
    }

    @Test
    public void createMinimalRevocationCertificateTest() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();

        PGPPublicKeyRing minimalRevocationCert = PGPainless.modifyKeyRing(secretKeys).createMinimalRevocationCertificate(
                SecretKeyRingProtector.unprotectedKeys(),
                RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED).withoutDescription());

        assertEquals(1, minimalRevocationCert.size());
        PGPPublicKey key = minimalRevocationCert.getPublicKey();
        assertEquals(secretKeys.getPublicKey().getKeyID(), key.getKeyID());
        assertEquals(1, CollectionUtils.iteratorToList(key.getSignatures()).size());
        assertFalse(key.getUserIDs().hasNext());
        assertFalse(key.getUserAttributes().hasNext());
        assertNull(key.getTrustData());
    }

    @Test
    public void createMinimalRevocationCertificateForFreshKeyTest()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@example.org>");

        PGPPublicKeyRing minimalRevocationCert = PGPainless.modifyKeyRing(secretKeys).createMinimalRevocationCertificate(
                SecretKeyRingProtector.unprotectedKeys(),
                RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED).withoutDescription());

        assertEquals(1, minimalRevocationCert.size());
        PGPPublicKey key = minimalRevocationCert.getPublicKey();
        assertEquals(secretKeys.getPublicKey().getKeyID(), key.getKeyID());
        assertEquals(1, CollectionUtils.iteratorToList(key.getSignatures()).size());
        assertFalse(key.getUserIDs().hasNext());
        assertFalse(key.getUserAttributes().hasNext());
        assertNull(key.getTrustData());
    }

    @Test
    public void createMinimalRevocationCertificate_wrongReason() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        assertThrows(IllegalArgumentException.class,
                () -> PGPainless.modifyKeyRing(secretKeys).createMinimalRevocationCertificate(
                        SecretKeyRingProtector.unprotectedKeys(),
                        RevocationAttributes.createCertificateRevocation()
                                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                                .withoutDescription()));
    }
}
