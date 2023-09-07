// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type

import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.ecc.EllipticCurve
import org.pgpainless.key.generation.type.ecc.ecdh.ECDH
import org.pgpainless.key.generation.type.ecc.ecdsa.ECDSA
import org.pgpainless.key.generation.type.eddsa.EdDSA
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RSA
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDH
import org.pgpainless.key.generation.type.xdh.XDHSpec
import java.security.spec.AlgorithmParameterSpec

@Suppress("INAPPLICABLE_JVM_NAME") // https://youtrack.jetbrains.com/issue/KT-31420
interface KeyType {

    /**
     * Return the encryption algorithm name.
     *
     * @return algorithm name.
     */
    val name: String

    /**
     * Return the public key algorithm.
     *
     * @return public key algorithm
     */
    val algorithm: PublicKeyAlgorithm

    /**
     * Return the strength of the key in bits.
     * @return strength of the key in bits
     */
    val bitStrength: Int

    /**
     * Return an implementation of {@link AlgorithmParameterSpec} that can be used to generate the key.
     *
     * @return algorithm parameter spec
     */
    val algorithmSpec: AlgorithmParameterSpec

    /**
     * Return true if the key that is generated from this type is able to carry the SIGN_DATA key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#SIGN_DATA}.
     *
     * @return true if the key can sign.
     */
    val canSign: Boolean
        @JvmName("canSign") get() = algorithm.signingCapable

    /**
     * Return true if the key that is generated from this type is able to carry the CERTIFY_OTHER key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#CERTIFY_OTHER}.
     *
     * @return true if the key is able to certify other keys
     */
    val canCertify: Boolean
        @JvmName("canCertify") get() = canSign

    /**
     * Return true if the key that is generated from this type is able to carry the AUTHENTICATION key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#AUTHENTICATION}.
     *
     * @return true if the key can be used for authentication purposes.
     */
    val canAuthenticate: Boolean
        @JvmName("canAuthenticate") get() = canSign

    /**
     * Return true if the key that is generated from this type is able to carry the ENCRYPT_COMMS key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS}.
     *
     * @return true if the key can encrypt communication
     */
    val canEncryptCommunication: Boolean
        @JvmName("canEncryptCommunication") get() = algorithm.encryptionCapable

    /**
     * Return true if the key that is generated from this type is able to carry the ENCRYPT_STORAGE key flag.
     * See {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_STORAGE}.
     *
     * @return true if the key can encrypt for storage
     */
    val canEncryptStorage: Boolean
        @JvmName("canEncryptStorage") get() = algorithm.encryptionCapable

    companion object {
        @JvmStatic
        fun RSA(length: RsaLength): RSA = RSA.withLength(length)

        @JvmStatic
        fun ECDH(curve: EllipticCurve): ECDH = ECDH.fromCurve(curve)

        @JvmStatic
        fun ECDSA(curve: EllipticCurve): ECDSA = ECDSA.fromCurve(curve)

        @JvmStatic
        fun EDDSA(curve: EdDSACurve): EdDSA = EdDSA.fromCurve(curve)

        @JvmStatic
        fun XDH(curve: XDHSpec): XDH = XDH.fromSpec(curve)
    }
}