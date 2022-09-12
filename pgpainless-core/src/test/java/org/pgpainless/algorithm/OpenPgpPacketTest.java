// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.bouncycastle.bcpg.PacketTags;
import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OpenPgpPacketTest {

    @Test
    public void testFromInvalidTag() {
        int tag = PacketTags.RESERVED;
        assertNull(OpenPgpPacket.fromTag(tag));
        assertThrows(NoSuchElementException.class,
                () -> OpenPgpPacket.requireFromTag(tag));
    }

    @Test
    public void testFromExistingTags() {
        for (OpenPgpPacket p : OpenPgpPacket.values()) {
            assertEquals(p, OpenPgpPacket.fromTag(p.getTag()));
            assertEquals(p, OpenPgpPacket.requireFromTag(p.getTag()));
        }
    }

    @Test
    public void testPKESKTagMatches() {
        assertEquals(PacketTags.PUBLIC_KEY_ENC_SESSION, OpenPgpPacket.PKESK.getTag());
    }
}
