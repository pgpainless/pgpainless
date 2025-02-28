// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertNull;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

public class UnprotectedKeysProtectorTest {

    private final UnprotectedKeysProtector protector = new UnprotectedKeysProtector();

    @Test
    public void testKeyProtectorReturnsNullDecryptor() throws PGPException {
        assertNull(protector.getDecryptor(0L));
    }

    @Test
    public void testKeyProtectorReturnsNullEncryptor() throws PGPException {
        assertNull(protector.getEncryptor(0L));
    }
}
