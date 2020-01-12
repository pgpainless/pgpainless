/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

import java.util.Arrays;

import org.junit.Test;
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
