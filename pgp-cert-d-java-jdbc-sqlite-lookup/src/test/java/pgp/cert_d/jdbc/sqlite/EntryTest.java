// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EntryTest {

    @Test
    public void simpleGetterTest() {
        Entry entry = new Entry(1, 123L, "eb85bb5fa33a75e15e944e63f231550c4f47e38e");

        assertEquals(1, entry.getId());
        assertEquals(123L, entry.getSubkeyId());
        assertEquals("eb85bb5fa33a75e15e944e63f231550c4f47e38e", entry.getCertificate());
    }
}
