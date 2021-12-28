// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.ecc.ecdh.ECDH;
import org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA;
import org.pgpainless.key.generation.type.eddsa.EdDSA;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.rsa.RSA;
import org.pgpainless.key.generation.type.xdh.XDH;
import org.pgpainless.key.generation.type.xdh.XDHSpec;

public interface KeyType {

    /**
     * Return the encryption algorithm name.
     *
     * @return algorithm name.
     */
    String getName();

    /**
     * Return the public key algorithm.
     *
     * @return public key algorithm
     */
    PublicKeyAlgorithm getAlgorithm();

    /**
     * Return the strength of the key in bits.
     * @return strength of the key in bits
     */
    int getBitStrength();

    /**
     * Return an implementation of {@link AlgorithmParameterSpec} that can be used to generate the key.
     *
     * @return algorithm parameter spec
     */
    AlgorithmParameterSpec getAlgorithmSpec();

    /**
     * Return true if the key that is generated from this type is able to carry the SIGN_DATA key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#SIGN_DATA}.
     *
     * @return true if the key can sign.
     */
    default boolean canSign() {
        return getAlgorithm().isSigningCapable();
    }

    /**
     * Return true if the key that is generated from this type is able to carry the CERTIFY_OTHER key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#CERTIFY_OTHER}.
     *
     * @return true if the key is able to certify other keys
     */
    default boolean canCertify() {
        return canSign();
    }

    /**
     * Return true if the key that is generated from this type is able to carry the AUTHENTICATION key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#AUTHENTICATION}.
     *
     * @return true if the key can be used for authentication purposes.
     */
    default boolean canAuthenticate() {
        return canSign();
    }

    /**
     * Return true if the key that is generated from this type is able to carry the ENCRYPT_COMMS key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS}.
     *
     * @return true if the key can encrypt communication
     */
    default boolean canEncryptCommunication() {
        return getAlgorithm().isEncryptionCapable();
    }

    /**
     * Return true if the key that is generated from this type is able to carry the ENCRYPT_STORAGE key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE}.
     *
     * @return true if the key can encrypt for storage
     */
    default boolean canEncryptStorage() {
        return getAlgorithm().isEncryptionCapable();
    }

    static KeyType RSA(RsaLength length) {
        return RSA.withLength(length);
    }

    static KeyType ECDH(EllipticCurve curve) {
        return ECDH.fromCurve(curve);
    }

    static KeyType ECDSA(EllipticCurve curve) {
        return ECDSA.fromCurve(curve);
    }

    static KeyType EDDSA(EdDSACurve curve) {
        return EdDSA.fromCurve(curve);
    }

    static KeyType XDH(XDHSpec curve) {
        return XDH.fromSpec(curve);
    }
}
