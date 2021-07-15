/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sop.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import sop.SessionKey;

public class SessionKeyTest {

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
}
