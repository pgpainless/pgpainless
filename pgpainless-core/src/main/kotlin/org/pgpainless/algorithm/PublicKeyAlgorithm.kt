// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.bcpg.PublicKeyUtils

/**
 * Enumeration of public key algorithms as defined in RFC4880, RFC9580, Persistent Symmetric Keys.
 *
 * @see [RFC4880: Public-Key Algorithms](https://tools.ietf.org/html/rfc4880#section-9.1)
 * @see
 *   [RFC9580: Public-Key Algorithms](https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms)
 * @see
 *   [Persistent Symmetric Keys in OpenPGP](https://www.ietf.org/archive/id/draft-ietf-openpgp-persistent-symmetric-keys-01.html#name-persistent-symmetric-key-al)
 */
enum class PublicKeyAlgorithm(val algorithmId: Int) {

    // RFC4880

    /** RSA capable of encryption and signatures. */
    RSA_GENERAL(1),

    /**
     * RSA with usage encryption.
     *
     * @deprecated see [Deprecation notice](https://tools.ietf.org/html/rfc4880#section-13.5)
     */
    @Deprecated("RSA_ENCRYPT is deprecated in favor of RSA_GENERAL", ReplaceWith("RSA_GENERAL"))
    RSA_ENCRYPT(2),

    /**
     * RSA with usage of creating signatures.
     *
     * @deprecated see [Deprecation notice](https://tools.ietf.org/html/rfc4880#section-13.5)
     */
    @Deprecated("RSA_SIGN is deprecated in favor of RSA_GENERAL", ReplaceWith("RSA_GENERAL"))
    RSA_SIGN(3),

    /** ElGamal with usage encryption. */
    ELGAMAL_ENCRYPT(16),

    /** Digital Signature Algorithm. */
    DSA(17),

    /** Elliptic Curve Diffie-Hellman. */
    ECDH(18),

    /** Elliptic Curve Digital Signature Algorithm. */
    ECDSA(19),

    /**
     * ElGamal General.
     *
     * @deprecated see [Deprecation notice](https://tools.ietf.org/html/rfc4880#section-13.8)
     */
    @Deprecated("ElGamal is deprecated") ELGAMAL_GENERAL(20),

    /** Diffie-Hellman key exchange algorithm. */
    DIFFIE_HELLMAN(21),

    /** Digital Signature Algorithm based on twisted Edwards Curves. */
    EDDSA_LEGACY(22),

    // RFC9580

    /** X25519 encryption algorithm. */
    X25519(25),

    /** X448 encryption algorithm. */
    X448(26),

    /** Ed25519 signature algorithm. */
    ED25519(27),

    /** Ed448 signature algorithm. */
    ED448(28),

    // Persistent Symmetric Keys in OpenPGP

    /**
     * AEAD can be used as a persistent key symmetric encryption algorithm for message encryption.
     *
     * @see
     *   [Persistent Symmetric Keys in OpenPGP](https://datatracker.ietf.org/doc/draft-ietf-openpgp-persistent-symmetric-keys/)
     */
    AEAD(128) {
        override val signingCapable = false
        override val encryptionCapable = true
    },

    /**
     * HMAC can be used as a persistent key symmetric signing algorithm for message signing.
     *
     * @see
     *   [Persistent Symmetric Keys in OpenPGP](https://datatracker.ietf.org/doc/draft-ietf-openpgp-persistent-symmetric-keys/)
     */
    HMAC(129) {
        override val signingCapable = true
        override val encryptionCapable = false
    };

    open val signingCapable: Boolean = PublicKeyUtils.isSigningAlgorithm(algorithmId)
    open val encryptionCapable: Boolean = PublicKeyUtils.isEncryptionAlgorithm(algorithmId)

    fun isSigningCapable(): Boolean = signingCapable

    fun isEncryptionCapable(): Boolean = encryptionCapable

    companion object {
        @JvmStatic
        fun fromId(id: Int): PublicKeyAlgorithm? {
            return values().firstOrNull { it.algorithmId == id }
        }

        @JvmStatic
        fun requireFromId(id: Int): PublicKeyAlgorithm {
            return fromId(id)
                ?: throw NoSuchElementException("No PublicKeyAlgorithm found for id $id")
        }
    }
}
