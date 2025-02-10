// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class PrimaryUserIdTest {

    @Test
    public void testGetPrimaryUserId() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit")
                .getPGPSecretKeyRing();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("mad_alice@wonderland.lit", SecretKeyRingProtector.unprotectedKeys())
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertEquals("alice@wonderland.lit", info.getPrimaryUserId());
    }
}
