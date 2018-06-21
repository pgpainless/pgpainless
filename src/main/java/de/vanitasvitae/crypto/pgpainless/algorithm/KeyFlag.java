/*
 * Copyright 2018 Paul Schaub.
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
package de.vanitasvitae.crypto.pgpainless.algorithm;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.sig.KeyFlags;

public enum KeyFlag {

    CERTIFY_OTHER(  KeyFlags.CERTIFY_OTHER),
    SIGN_DATA(      KeyFlags.SIGN_DATA),
    ENCRYPT_COMMS(  KeyFlags.ENCRYPT_COMMS),
    ENCRYPT_STORAGE(KeyFlags.ENCRYPT_STORAGE),
    SPLIT(          KeyFlags.SPLIT),
    AUTHENTICATION( KeyFlags.AUTHENTICATION),
    SHARED(         KeyFlags.SHARED),
    ;

    private final int flag;

    KeyFlag(int flag) {
        this.flag = flag;
    }

    public int getFlag() {
        return flag;
    }

    public static List<KeyFlag> fromInteger(int bitmask) {
        List<KeyFlag> flags = new ArrayList<>();
        for (KeyFlag f : KeyFlag.values()) {
            if ((bitmask & f.flag) != 0) {
                flags.add(f);
            }
        }
        return flags;
    }
}
