// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;

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

    /**
     * Returns indication that a contained secret key has S2K of a type GNU_DUMMY_S2K.
     *
     * @return true if secret key has S2K of a type GNU_DUMMY_S2K, false if there is public key only,
     *         or S2K on the secret key is absent or not of a type GNU_DUMMY_S2K.
     */
    public boolean hasDummyS2K() {
        return secretKey != null && hasDummyS2K(secretKey);
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
                throw new IllegalArgumentException("Not an elliptic curve public key (" + algorithm + ")");
        }
        return getCurveName(key);
    }

    public static String getCurveName(ECPublicBCPGKey key) {
        ASN1ObjectIdentifier identifier = key.getCurveOID();

        // Workaround for ECUtil not recognizing ed25519
        if (identifier.equals(GNUObjectIdentifiers.Ed25519)) {
            return EdDSACurve._Ed25519.getName();
        }

        return ECUtil.getCurveName(identifier);
    }

    /**
     * Returns indication that a secret key is encrypted.
     *
     * @param secretKey A secret key to examine.
     * @return true if secret key is encrypted, false otherwise.
     */
    public static boolean isEncrypted(PGPSecretKey secretKey) {
        return secretKey.getS2KUsage() != 0;
    }

    /**
     * Returns indication that a secret key is not encrypted.
     *
     * @param secretKey A secret key to examine.
     * @return true if secret key is encrypted, false otherwise.
     */
    public static boolean isDecrypted(PGPSecretKey secretKey) {
        return secretKey.getS2KUsage() == 0;
    }

    /**
     * Returns indication that a secret key has S2K of a type GNU_DUMMY_S2K.
     *
     * @param secretKey A secret key to examine.
     * @return true if secret key has S2K of a type GNU_DUMMY_S2K, false otherwise.
     */
    public static boolean hasDummyS2K(PGPSecretKey secretKey) {
        final S2K s2k = secretKey.getS2K();
        return s2k != null && s2k.getType() == S2K.GNU_DUMMY_S2K;
    }
}
