// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

/**
 * Enumeration of public key algorithms as defined in RFC4880.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-9.1">RFC4880: Public-Key Algorithms</a>
 */
public enum PublicKeyAlgorithm {

    /**
     * RSA capable of encryption and signatures.
     */
    RSA_GENERAL     (PublicKeyAlgorithmTags.RSA_GENERAL, true, true),

    /**
     * RSA with usage encryption.
     *
     * @deprecated see https://tools.ietf.org/html/rfc4880#section-13.5
     */
    @Deprecated
    RSA_ENCRYPT     (PublicKeyAlgorithmTags.RSA_ENCRYPT, false, true),

    /**
     * RSA with usage of creating signatures.
     *
     * @deprecated see https://tools.ietf.org/html/rfc4880#section-13.5
     */
    @Deprecated
    RSA_SIGN        (PublicKeyAlgorithmTags.RSA_SIGN, true, false),

    /**
     * ElGamal with usage encryption.
     */
    ELGAMAL_ENCRYPT (PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, false, true),

    /**
     * Digital Signature Algorithm.
     */
    DSA             (PublicKeyAlgorithmTags.DSA, true, false),

    /**
     * EC is deprecated.
     * @deprecated use {@link #ECDH} instead.
     */
    @Deprecated
    EC              (PublicKeyAlgorithmTags.EC, false, true),

    /**
     * Elliptic Curve Diffie-Hellman.
     */
    ECDH            (PublicKeyAlgorithmTags.ECDH, false, true),

    /**
     * Elliptic Curve Digital Signature Algorithm.
     */
    ECDSA           (PublicKeyAlgorithmTags.ECDSA, true, false),

    /**
     * ElGamal General.
     *
     * @deprecated see https://tools.ietf.org/html/rfc4880#section-13.8
     */
    @Deprecated
    ELGAMAL_GENERAL (PublicKeyAlgorithmTags.ELGAMAL_GENERAL, true, true),

    /**
     * Diffie-Hellman key exchange algorithm.
     */
    DIFFIE_HELLMAN  (PublicKeyAlgorithmTags.DIFFIE_HELLMAN, false, true),

    /**
     * Digital Signature Algorithm based on twisted Edwards Curves.
     */
    EDDSA           (PublicKeyAlgorithmTags.EDDSA, true, false),
    ;

    private static final Map<Integer, PublicKeyAlgorithm> MAP = new ConcurrentHashMap<>();

    static {
        for (PublicKeyAlgorithm p : PublicKeyAlgorithm.values()) {
            MAP.put(p.algorithmId, p);
        }
    }

    /**
     * Return the {@link PublicKeyAlgorithm} that corresponds to the provided algorithm id.
     * If an invalid id is provided, null is returned.
     *
     * @param id numeric algorithm id
     * @return algorithm
     */
    public static PublicKeyAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;
    private final boolean signingCapable;
    private final boolean encryptionCapable;

    PublicKeyAlgorithm(int algorithmId, boolean signingCapable, boolean encryptionCapable) {
        this.algorithmId = algorithmId;
        this.signingCapable = signingCapable;
        this.encryptionCapable = encryptionCapable;
    }

    /**
     * Return the numeric identifier of the public key algorithm.
     *
     * @return id
     */
    public int getAlgorithmId() {
        return algorithmId;
    }

    /**
     * Return true if this public key algorithm is able to create signatures.
     *
     * @return true if the algorithm can sign
     */
    public boolean isSigningCapable() {
        return signingCapable;
    }

    /**
     * Return true if this public key algorithm can be used as an encryption algorithm.
     *
     * @return true if the algorithm can encrypt
     */
    public boolean isEncryptionCapable() {
        return encryptionCapable;
    }
}
