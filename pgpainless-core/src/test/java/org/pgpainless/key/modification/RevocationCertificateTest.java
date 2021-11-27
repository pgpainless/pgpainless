// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;

public class RevocationCertificateTest {

    @Test
    public void createRevocationCertificateTest() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();

        PGPSignature revocation = PGPainless.modifyKeyRing(secretKeys)
                .createRevocationCertificate(SecretKeyRingProtector.unprotectedKeys(),
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
}
