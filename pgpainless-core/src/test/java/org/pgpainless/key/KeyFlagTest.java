// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.KeyFlag;

public class KeyFlagTest {

    @Test
    public void hasKeyFlagTest() {
        int mask = KeyFlag.toBitmask(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA);
        assertEquals(0x23, mask);
        assertEquals(Arrays.asList(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.AUTHENTICATION),
                KeyFlag.fromBitmask(mask));

        assertTrue(KeyFlag.hasKeyFlag(mask, KeyFlag.CERTIFY_OTHER));
        assertTrue(KeyFlag.hasKeyFlag(mask, KeyFlag.AUTHENTICATION));
        assertTrue(KeyFlag.hasKeyFlag(mask, KeyFlag.SIGN_DATA));

        assertFalse(KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_STORAGE));
        assertFalse(KeyFlag.hasKeyFlag(mask, KeyFlag.SHARED));
    }
}
