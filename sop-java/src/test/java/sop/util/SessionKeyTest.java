// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import sop.SessionKey;

public class SessionKeyTest {

    @Test
    public void fromStringTest() {
        String string = "9:FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD";
        SessionKey sessionKey = SessionKey.fromString(string);
        assertEquals(string, sessionKey.toString());
    }

    @Test
    public void toStringTest() {
        SessionKey sessionKey = new SessionKey((byte) 9, HexUtil.hexToBytes("FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD"));
        assertEquals("9:FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD", sessionKey.toString());
    }

    @Test
    public void equalsTest() {
        SessionKey s1 = new SessionKey((byte) 9, HexUtil.hexToBytes("FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD"));
        SessionKey s2 = new SessionKey((byte) 9, HexUtil.hexToBytes("FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD"));
        SessionKey s3 = new SessionKey((byte) 4, HexUtil.hexToBytes("FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD"));
        SessionKey s4 = new SessionKey((byte) 9, HexUtil.hexToBytes("19125CD57392BAB7037C7078359FCA4BEAF687F4025CBF9F7BCD8059CACC14FB"));
        SessionKey s5 = new SessionKey((byte) 4, HexUtil.hexToBytes("19125CD57392BAB7037C7078359FCA4BEAF687F4025CBF9F7BCD8059CACC14FB"));

        assertEquals(s1, s1);
        assertEquals(s1, s2);
        assertEquals(s1.hashCode(), s2.hashCode());
        assertNotEquals(s1, s3);
        assertNotEquals(s1.hashCode(), s3.hashCode());
        assertNotEquals(s1, s4);
        assertNotEquals(s1.hashCode(), s4.hashCode());
        assertNotEquals(s4, s5);
        assertNotEquals(s4.hashCode(), s5.hashCode());
        assertNotEquals(s1, null);
        assertNotEquals(s1, "FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD");
    }

    @Test
    public void fromString_missingAlgorithmIdThrows() {
        String missingAlgorithId = "FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD";
        assertThrows(IllegalArgumentException.class, () -> SessionKey.fromString(missingAlgorithId));
    }

    @Test
    public void fromString_wrongDivider() {
        String semicolonDivider = "9;FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD";
        assertThrows(IllegalArgumentException.class, () -> SessionKey.fromString(semicolonDivider));
    }
}
