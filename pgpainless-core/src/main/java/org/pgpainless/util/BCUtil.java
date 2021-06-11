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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;

public class BCUtil {

    public static InputStream getPgpDecoderInputStream(@Nonnull byte[] bytes)
            throws IOException {
        return getPgpDecoderInputStream(new ByteArrayInputStream(bytes));
    }

    public static InputStream getPgpDecoderInputStream(@Nonnull InputStream inputStream)
            throws IOException {
        return PGPUtil.getDecoderStream(inputStream);
    }

    public static int getBitStrenght(PGPPublicKey key) {
        int bitStrength = key.getBitStrength();

        if (bitStrength == -1) {
            // TODO: BC's PGPPublicKey.getBitStrength() does fail for some keys (EdDSA, X25519)
            //  Manually set the bit strength.

            ASN1ObjectIdentifier oid = ((ECPublicBCPGKey) key.getPublicKeyPacket().getKey()).getCurveOID();
            if (oid.getId().equals("1.3.6.1.4.1.11591.15.1")) {
                // ed25519 is 256 bits
                bitStrength = 256;
            } else if (oid.getId().equals("1.3.6.1.4.1.3029.1.5.1")) {
                // curvey25519 is 256 bits
                bitStrength = 256;
            } else {
                throw new RuntimeException("Unknown curve: " + oid.getId());
            }

        }
        return bitStrength;
    }

}
