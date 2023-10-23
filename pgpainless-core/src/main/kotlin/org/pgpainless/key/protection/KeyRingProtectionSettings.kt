// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

/**
 * Secret key protection settings for iterated and salted S2K. The salt gets randomly chosen by the
 * library each time. Note, that the s2kCount is the already encoded single-octet number.
 *
 * @param encryptionAlgorithm encryption algorithm
 * @param hashAlgorithm hash algorithm
 * @param s2kCount encoded (!) s2k iteration count
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-3.7.1.3">Encoding Formula</a>
 */
data class KeyRingProtectionSettings(
    val encryptionAlgorithm: SymmetricKeyAlgorithm,
    val hashAlgorithm: HashAlgorithm,
    val s2kCount: Int
) {

    /**
     * Create a [KeyRingProtectionSettings] object using the given encryption algorithm,
     * [HashAlgorithm.SHA1] and 65536 iterations. It is okay to use SHA1 here, since we don't care
     * about collisions.
     *
     * @param encryptionAlgorithm encryption algorithm
     */
    constructor(
        encryptionAlgorithm: SymmetricKeyAlgorithm
    ) : this(encryptionAlgorithm, HashAlgorithm.SHA1, 0x60)

    init {
        require(encryptionAlgorithm != SymmetricKeyAlgorithm.NULL) {
            "Unencrypted is not allowed here!"
        }
        require(s2kCount > 0) { "s2kCount cannot be less than 1." }
    }

    companion object {

        /**
         * Secure default settings using [SymmetricKeyAlgorithm.AES_256], [HashAlgorithm.SHA256] and
         * an iteration count of 65536.
         *
         * @return secure protection settings
         */
        @JvmStatic
        fun secureDefaultSettings() =
            KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA256, 0x60)
    }
}
