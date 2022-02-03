// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SpecialNamesTest {

    @Test
    public void bothTrustRootNotationsAreRecognized() {
        assertEquals("trust-root", SpecialNames.lookupSpecialName("trust-root"));
        assertEquals("trust-root", SpecialNames.lookupSpecialName("TRUST-ROOT"));
    }

    @Test
    public void testInvalidSpecialNameReturnsNull() {
        assertNull(SpecialNames.lookupSpecialName("invalid"));
        assertNull(SpecialNames.lookupSpecialName("trust root"));
        assertNull(SpecialNames.lookupSpecialName("writelock"));
    }
}
