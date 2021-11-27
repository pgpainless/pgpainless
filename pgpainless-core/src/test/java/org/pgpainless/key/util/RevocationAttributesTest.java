// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RevocationAttributesTest {

    @Test
    public void testIsHardRevocationReason() {
        // No reason and key compromised are hard revocation reasons
        assertTrue(RevocationAttributes.Reason.isHardRevocation(RevocationAttributes.Reason.NO_REASON));
        assertTrue(RevocationAttributes.Reason.isHardRevocation(RevocationAttributes.Reason.KEY_COMPROMISED));

        // others are soft
        assertFalse(RevocationAttributes.Reason.isHardRevocation(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID));
        assertFalse(RevocationAttributes.Reason.isHardRevocation(RevocationAttributes.Reason.KEY_RETIRED));
        assertFalse(RevocationAttributes.Reason.isHardRevocation(RevocationAttributes.Reason.KEY_SUPERSEDED));
    }

    @Test
    public void fromReasonCode() {
        assertEquals(RevocationAttributes.Reason.NO_REASON, RevocationAttributes.Reason.fromCode((byte) 0));
        assertEquals(RevocationAttributes.Reason.KEY_SUPERSEDED, RevocationAttributes.Reason.fromCode((byte) 1));
        assertEquals(RevocationAttributes.Reason.KEY_COMPROMISED, RevocationAttributes.Reason.fromCode((byte) 2));
        assertEquals(RevocationAttributes.Reason.KEY_RETIRED, RevocationAttributes.Reason.fromCode((byte) 3));
        assertEquals(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID, RevocationAttributes.Reason.fromCode((byte) 32));
    }
}
