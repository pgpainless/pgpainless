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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
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
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getEmilKey();

        OpenPGPSignature revocation = api.modify(secretKeys)
                .createRevocation(SecretKeyRingProtector.unprotectedKeys(),
                        RevocationAttributes.createKeyRevocation()
                                .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                                .withoutDescription());

        assertNotNull(revocation);

        assertTrue(api.inspect(secretKeys).isKeyValidlyBound(secretKeys.getKeyIdentifier()));

        // merge key and revocation certificate
        PGPSecretKeyRing revokedKey = KeyRingUtils.keysPlusSecretKey(
                secretKeys.getPGPSecretKeyRing(),
                KeyRingUtils.secretKeyPlusSignature(secretKeys.getPrimarySecretKey().getPGPSecretKey(), revocation.getSignature()));

        assertFalse(api.inspect(api.toKey(revokedKey)).isKeyValidlyBound(secretKeys.getKeyIdentifier()));
    }

    @Test
    public void createMinimalRevocationCertificateTest() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getEmilKey();

        OpenPGPCertificate minimalRevocationCert = api.modify(secretKeys).createMinimalRevocationCertificate(
                SecretKeyRingProtector.unprotectedKeys(),
                RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED).withoutDescription());

        assertEquals(1, minimalRevocationCert.getPGPKeyRing().size());
        PGPPublicKey key = minimalRevocationCert.getPrimaryKey().getPGPPublicKey();
        assertEquals(secretKeys.getKeyIdentifier(), key.getKeyIdentifier());
        assertEquals(1, CollectionUtils.iteratorToList(key.getSignatures()).size());
        assertFalse(key.getUserIDs().hasNext());
        assertFalse(key.getUserAttributes().hasNext());
        assertNull(key.getTrustData());

        OpenPGPCertificate originalCert = secretKeys.toCertificate();
        OpenPGPCertificate mergedCert = api.mergeCertificate(originalCert, minimalRevocationCert);

        assertTrue(api.inspect(mergedCert).getRevocationState().isSoftRevocation());
    }

    @Test
    public void createMinimalRevocationCertificateForFreshKeyTest() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice <alice@example.org>");

        OpenPGPCertificate minimalRevocationCert = api.modify(secretKeys).createMinimalRevocationCertificate(
                SecretKeyRingProtector.unprotectedKeys(),
                RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED).withoutDescription());

        assertEquals(1, minimalRevocationCert.getKeys().size());
        PGPPublicKey key = minimalRevocationCert.getPGPPublicKeyRing().getPublicKey();
        assertEquals(secretKeys.getKeyIdentifier(), key.getKeyIdentifier());
        assertEquals(1, CollectionUtils.iteratorToList(key.getSignatures()).size());
        assertFalse(key.getUserIDs().hasNext());
        assertFalse(key.getUserAttributes().hasNext());
        assertNull(key.getTrustData());

        OpenPGPCertificate originalCert = secretKeys.toCertificate();
        OpenPGPCertificate mergedCert = api.mergeCertificate(originalCert, minimalRevocationCert);

        assertTrue(api.inspect(mergedCert).getRevocationState().isSoftRevocation());
    }

    @Test
    public void createMinimalRevocationCertificate_wrongReason() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        assertThrows(IllegalArgumentException.class,
                () -> api.modify(secretKeys).createMinimalRevocationCertificate(
                        SecretKeyRingProtector.unprotectedKeys(),
                        RevocationAttributes.createCertificateRevocation()
                                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                                .withoutDescription()));
    }
}
