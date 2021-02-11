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
package org.pgpainless.key.info;

import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.algorithm.PublicKeyAlgorithm;

public class KeyInfo {

    private final PGPSecretKey secretKey;
    private final PGPPublicKey publicKey;

    public KeyInfo(PGPSecretKey secretKey) {
        this.secretKey = secretKey;
        this.publicKey = secretKey.getPublicKey();
    }

    public KeyInfo(PGPPublicKey publicKey) {
        this.publicKey = publicKey;
        this.secretKey = null;
    }

    public static String getCurveName(PGPPublicKey publicKey) {
        PublicKeyAlgorithm algorithm = PublicKeyAlgorithm.fromId(publicKey.getAlgorithm());
        ECPublicBCPGKey key;
        switch (algorithm) {
            case ECDSA: {
                key = (ECDSAPublicBCPGKey) publicKey.getPublicKeyPacket().getKey();
                break;
            }
            case ECDH: {
                key = (ECDHPublicBCPGKey) publicKey.getPublicKeyPacket().getKey();
                break;
            }
            case EDDSA: {
                key = (EdDSAPublicBCPGKey) publicKey.getPublicKeyPacket().getKey();
                break;
            }
            default:
                throw new IllegalArgumentException("Not a EC public key (" + algorithm + ")");
        }
        return getCurveName(key);
    }

    public static String getCurveName(ECPublicBCPGKey key) {
        return ECUtil.getCurveName(key.getCurveOID());
    }
}
