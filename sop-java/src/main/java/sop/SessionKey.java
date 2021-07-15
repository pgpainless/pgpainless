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
package sop;

import java.util.Arrays;

import sop.util.HexUtil;

public class SessionKey {

    private final byte algorithm;
    private final byte[] sessionKey;

    public SessionKey(byte algorithm, byte[] sessionKey) {
        this.algorithm = algorithm;
        this.sessionKey = sessionKey;
    }

    /**
     * Return the symmetric algorithm octet.
     *
     * @return algorithm id
     */
    public byte getAlgorithm() {
        return algorithm;
    }

    /**
     * Return the session key.
     *
     * @return session key
     */
    public byte[] getKey() {
        return sessionKey;
    }

    @Override
    public int hashCode() {
        return getAlgorithm() * 17 + Arrays.hashCode(getKey());
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (this == other) {
            return true;
        }
        if (!(other instanceof SessionKey)) {
            return false;
        }

        SessionKey otherKey = (SessionKey) other;
        return getAlgorithm() == otherKey.getAlgorithm() && Arrays.equals(getKey(), otherKey.getKey());
    }

    @Override
    public String toString() {
        return "" + (int) getAlgorithm() + ':' + HexUtil.bytesToHex(sessionKey);
    }
}
