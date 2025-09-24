// SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.openpgp.api.MessageEncryptionMechanism

/**
 * AEAD Algorithm.
 *
 * @param algorithmId numeric algorithm id
 * @param ivLength length of the initialization vector
 * @param tagLength length of the tag
 * @see
 *   [RFC9580 - AEAD Algorithms](https://www.rfc-editor.org/rfc/rfc9580.html#name-aead-algorithms)
 */
enum class AEADAlgorithm(val algorithmId: Int, val ivLength: Int, val tagLength: Int) {

    /**
     * Encrypt-then-Authenticate-then-Translate mode.
     *
     * @see [RFC9580 - EAX Mode](https://www.rfc-editor.org/rfc/rfc9580.html#name-eax-mode)
     */
    EAX(1, 16, 16),

    /**
     * Offset-Codebook mode. OCB is mandatory to implement in crypto-refresh. Favored by GnuPG. Is
     * not yet FIPS compliant, but supported by most implementations and therefore favorable.
     *
     * @see [RFC9580 - OCB Mode](https://www.rfc-editor.org/rfc/rfc9580.html#name-ocb-mode)
     */
    OCB(2, 15, 16),

    /**
     * Galois/Counter-Mode. GCM is controversial. Some say it is hard to get right. Some
     * implementations like GnuPG therefore avoid it. May be necessary to achieve FIPS compliance.
     *
     * @see [RFC9580 - GCM Mode](https://www.rfc-editor.org/rfc/rfc9580.html#name-gcm-mode)
     */
    GCM(3, 12, 16),
    ;

    /**
     * Return a [MessageEncryptionMechanism] instance representing AEAD using this algorithm and the
     * given [SymmetricKeyAlgorithm].
     *
     * @param ciphermode symmetric key algorithm
     * @return MessageEncryptionMechanism representing aead(this, ciphermode)
     */
    fun toMechanism(ciphermode: SymmetricKeyAlgorithm): MessageEncryptionMechanism =
        MessageEncryptionMechanism.aead(ciphermode.algorithmId, this.algorithmId)

    companion object {

        /**
         * Parse an [AEADAlgorithm] from an algorithm id. If no matching [AEADAlgorithm] is known,
         * return `null`.
         *
         * @param id algorithm id
         * @return aeadAlgorithm or null
         */
        @JvmStatic
        fun fromId(id: Int): AEADAlgorithm? {
            return values().firstOrNull { algorithm -> algorithm.algorithmId == id }
        }

        /**
         * Parse an [AEADAlgorithm] from an algorithm id. If no matching [AEADAlgorithm] is known,
         * throw a [NoSuchElementException].
         *
         * @param id algorithm id
         * @return aeadAlgorithm
         * @throws NoSuchElementException for unknown algorithm ids
         */
        @JvmStatic
        fun requireFromId(id: Int): AEADAlgorithm {
            return fromId(id) ?: throw NoSuchElementException("No AEADAlgorithm found for id $id")
        }
    }
}
