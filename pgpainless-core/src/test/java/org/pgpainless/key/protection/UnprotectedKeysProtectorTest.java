// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertNull;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

public class UnprotectedKeysProtectorTest {

    private final UnprotectedKeysProtector protector = new UnprotectedKeysProtector();

    @Test
    public void testKeyProtectorReturnsNullDecryptor() throws PGPException {
        assertNull(protector.getDecryptor(new KeyIdentifier(0L)));
    }
}
