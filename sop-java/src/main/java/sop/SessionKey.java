// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
