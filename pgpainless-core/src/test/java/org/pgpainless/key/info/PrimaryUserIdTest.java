// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class PrimaryUserIdTest {

    @Test
    public void testGetPrimaryUserId() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().simpleEcKeyRing("alice@wonderland.lit");
        secretKeys = api.modify(secretKeys)
                .addUserId("mad_alice@wonderland.lit", SecretKeyRingProtector.unprotectedKeys())
                .done();

        KeyRingInfo info = api.inspect(secretKeys);
        assertEquals("alice@wonderland.lit", info.getPrimaryUserId());
    }
}
