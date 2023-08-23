// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * Enumeration of public key algorithms as defined in RFC4880.
 *
 * See [RFC4880: Public-Key Algorithms](https://tools.ietf.org/html/rfc4880#section-9.1)
 */
enum class PublicKeyAlgorithm(
        val algorithmId: Int,
        val signingCapable: Boolean,
        val encryptionCapable: Boolean) {

    /**
     * RSA capable of encryption and signatures.
     */
    RSA_GENERAL     (1, true, true),

    /**
     * RSA with usage encryption.
     *
     * @deprecated see <a href="https://tools.ietf.org/html/rfc4880#section-13.5">Deprecation notice</a>
     */
    @Deprecated("RSA_ENCRYPT is deprecated in favor of RSA_GENERAL",
            ReplaceWith("RSA_GENERAL"))
    RSA_ENCRYPT     (2, false, true),

    /**
     * RSA with usage of creating signatures.
     *
     * @deprecated see <a href="https://tools.ietf.org/html/rfc4880#section-13.5">Deprecation notice</a>
     */
    @Deprecated("RSA_SIGN is deprecated in favor of RSA_GENERAL",
            ReplaceWith("RSA_GENERAL"))
    RSA_SIGN        (3, true, false),

    /**
     * ElGamal with usage encryption.
     */
    ELGAMAL_ENCRYPT (16, false, true),

    /**
     * Digital Signature Algorithm.
     */
    DSA             (17, true, false),

    /**
     * Elliptic Curve Diffie-Hellman.
     */
    ECDH            (18, false, true),

    /**
     * Elliptic Curve Digital Signature Algorithm.
     */
    ECDSA           (19, true, false),

    /**
     * ElGamal General.
     *
     * @deprecated see <a href="https://tools.ietf.org/html/rfc4880#section-13.8">Deprecation notice</a>
     */
    @Deprecated("ElGamal is deprecated")
    ELGAMAL_GENERAL (20, true, true),

    /**
     * Diffie-Hellman key exchange algorithm.
     */
    DIFFIE_HELLMAN  (21, false, true),

    /**
     * Digital Signature Algorithm based on twisted Edwards Curves.
     */
    EDDSA           (22, true, false),
    ;

    fun isSigningCapable(): Boolean = signingCapable
    fun isEncryptionCapable(): Boolean = encryptionCapable

    companion object {
        @JvmStatic
        fun fromId(id: Int): PublicKeyAlgorithm? {
            return values().firstOrNull {
                it.algorithmId == id
            }
        }

        @JvmStatic
        fun requireFromId(id: Int): PublicKeyAlgorithm {
            return fromId(id) ?:
            throw NoSuchElementException("No PublicKeyAlgorithm found for id $id")
        }
    }
}