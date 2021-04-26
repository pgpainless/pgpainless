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
import org.bouncycastle.bcpg.S2K;
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

    public String getCurveName() {
        return getCurveName(publicKey);
    }

    /**
     * Returns indication that a contained secret key is encrypted.
     *
     * @return true if secret key is encrypted, false if secret key is not encrypted or there is public key only.
     */
    public boolean isEncrypted() {
        return secretKey != null && isEncrypted(secretKey);
    }

    /**
     * Returns indication that a contained secret key is not encrypted.
     *
     * @return true if secret key is not encrypted or there is public key only, false if secret key is encrypted.
     */
    public boolean isDecrypted() {
        return secretKey == null || isDecrypted(secretKey);
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

    /**
     * Returns indication that a secret key is encrypted.
     *
     * @param secretKey A secret key to examine.
     * @return true if secret key is encrypted, false otherwise.
     */
    public static boolean isEncrypted(PGPSecretKey secretKey) {
        return secretKey.getS2KUsage() != 0 && secretKey.getS2K().getType() != S2K.GNU_DUMMY_S2K;
    }

    /**
     * Returns indication that a secret key is not encrypted.
     *
     * @param secretKey A secret key to examine.
     * @return true if secret key is encrypted, false otherwise.
     */
    public static boolean isDecrypted(PGPSecretKey secretKey) {
        return secretKey.getS2KUsage() == 0 || secretKey.getS2K().getType() == S2K.GNU_DUMMY_S2K;
    }
}
