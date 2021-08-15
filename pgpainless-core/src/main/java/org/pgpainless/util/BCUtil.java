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

}
