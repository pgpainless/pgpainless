// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.openpgp.PGPPublicKey;

public final class BCUtil {

    private BCUtil() {

    }

    /**
     * Utility method to get the bit strength of OpenPGP keys.
     * Bouncycastle is lacking support for some keys (eg. EdDSA, X25519), so this method
     * manually derives the bit strength from the keys curves OID.
     *
     * @param key key
     * @return bit strength
     */
    public static int getBitStrength(PGPPublicKey key) throws NoSuchAlgorithmException {
        int bitStrength = key.getBitStrength();

        if (bitStrength == -1) {
            // BC's PGPPublicKey.getBitStrength() does fail for some keys (EdDSA, X25519)
            // therefore we manually set the bit strength.
            // see https://github.com/bcgit/bc-java/issues/972

            ASN1ObjectIdentifier oid = ((ECPublicBCPGKey) key.getPublicKeyPacket().getKey()).getCurveOID();
            if (oid.getId().equals("1.3.6.1.4.1.11591.15.1")) {
                // ed25519 is 256 bits
                bitStrength = 256;
            } else if (oid.getId().equals("1.3.6.1.4.1.3029.1.5.1")) {
                // curvey25519 is 256 bits
                bitStrength = 256;
            } else {
                throw new NoSuchAlgorithmException("Unknown curve: " + oid.getId());
            }

        }
        return bitStrength;
    }


    /**
     * A constant time equals comparison - does not terminate early if
     * test will fail. For best results always pass the expected value
     * as the first parameter.
     *
     * @param expected first array
     * @param supplied second array
     * @return true if arrays equal, false otherwise.
     */
    public static boolean constantTimeAreEqual(
            char[]  expected,
            char[]  supplied) {
        if (expected == null || supplied == null) {
            return false;
        }

        if (expected == supplied) {
            return true;
        }

        int len = (expected.length < supplied.length) ? expected.length : supplied.length;

        int nonEqual = expected.length ^ supplied.length;

        // do the char-wise comparison
        for (int i = 0; i != len; i++) {
            nonEqual |= (expected[i] ^ supplied[i]);
        }
        // If supplied is longer than expected, iterate over rest of supplied with NOPs
        for (int i = len; i < supplied.length; i++) {
            nonEqual |= ((byte) supplied[i] ^ (byte) ~supplied[i]);
        }

        return nonEqual == 0;
    }

}
