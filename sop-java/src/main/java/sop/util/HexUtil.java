// Copyright 2021 Paul Schaub, @maybeWeCouldStealAVan, @Dave L.
// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.util;

public class HexUtil {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Encode a byte array to a hex string.
     *
     * @see <a href="https://stackoverflow.com/a/9855338">
     *     How to convert a byte array to a hex string in Java?</a>
     * @param bytes bytes
     * @return hex encoding
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Decode a hex string into a byte array.
     *
     * @see <a href="https://stackoverflow.com/a/140861">
     *     Convert a string representation of a hex dump to a byte array using Java?</a>
     * @param s hex string
     * @return decoded byte array
     */
    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
