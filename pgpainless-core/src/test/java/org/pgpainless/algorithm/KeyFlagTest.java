// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

public class KeyFlagTest {

    @Test
    public void testEmptyBitmaskHasNoFlags() {
        int bitmask = KeyFlag.toBitmask();
        assertEquals(0, bitmask);
        for (KeyFlag flag : KeyFlag.values()) {
            assertFalse(KeyFlag.hasKeyFlag(bitmask, flag));
        }
    }

    @Test
    public void testEmptyBitmaskToKeyFlags() {
        int emptyMask = 0;
        List<KeyFlag> flags = KeyFlag.fromBitmask(emptyMask);
        assertTrue(flags.isEmpty());
    }

    @Test
    public void testSingleBitmaskToKeyFlags() {
        for (KeyFlag flag : KeyFlag.values()) {
            int singleMask = KeyFlag.toBitmask(flag);
            List<KeyFlag> singletonList = KeyFlag.fromBitmask(singleMask);
            assertEquals(1, singletonList.size());
            assertEquals(flag, singletonList.get(0));
        }
    }

    @Test
    public void testKeyFlagsToBitmaskToList() {
        int bitMask = KeyFlag.toBitmask(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);
        List<KeyFlag> flags = KeyFlag.fromBitmask(bitMask);

        assertEquals(2, flags.size());
        assertTrue(flags.contains(KeyFlag.ENCRYPT_COMMS));
        assertTrue(flags.contains(KeyFlag.ENCRYPT_STORAGE));
    }

    @Test
    public void testSingleKeyFlagToBitmask() {
        for (KeyFlag flag : KeyFlag.values()) {
            int bitmask = KeyFlag.toBitmask(flag);
            assertEquals(flag.getFlag(), bitmask);
        }
    }

    @Test
    public void testDuplicateFlagsDoNotChangeMask() {
        int mask = KeyFlag.toBitmask(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_COMMS);
        assertEquals(KeyFlag.toBitmask(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE), mask);
    }

    @Test
    public void testMaskHasNot() {
        int mask = KeyFlag.toBitmask(KeyFlag.ENCRYPT_STORAGE);
        assertFalse(KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_COMMS));
    }

    @Test
    public void testMaskContainsNone() {
        int mask = KeyFlag.toBitmask(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);

        assertFalse(KeyFlag.containsAny(mask, KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER));
    }

    @Test
    public void testContainsAnyContainsAllExact() {
        int mask = KeyFlag.toBitmask(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS);
        assertTrue(KeyFlag.containsAny(mask, KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS));
    }

    @Test
    public void testContainsAnyContainsAll() {
        int mask = KeyFlag.toBitmask(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.AUTHENTICATION);
        assertTrue(KeyFlag.containsAny(mask, KeyFlag.SIGN_DATA, KeyFlag.AUTHENTICATION));
    }

    @Test
    public void testContainsAnyContainsSome() {
        int mask = KeyFlag.toBitmask(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.AUTHENTICATION);
        assertTrue(KeyFlag.containsAny(mask, KeyFlag.CERTIFY_OTHER));
    }
}
