// SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.openpgp.api.MessageEncryptionMechanism

enum class AEADAlgorithm(val algorithmId: Int, val ivLength: Int, val tagLength: Int) {

    /**
     * Encrypt-then-Authenticate-then-Translate mode.
     * https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-eax-mode
     */
    EAX(1, 16, 16),

    /**
     * Offset-Codebook mode. OCB is mandatory to implement in crypto-refresh. Favored by GnuPG. Is
     * not yet FIPS compliant, but supported by most implementations and therefore favorable.
     * https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-ocb-mode
     */
    OCB(2, 15, 16),

    /**
     * Galois/Counter-Mode. GCM is controversial. Some say it is hard to get right. Some
     * implementations like GnuPG therefore avoid it. May be necessary to achieve FIPS compliance.
     * https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-gcm-mode
     */
    GCM(3, 12, 16),
    ;

    fun toMechanism(ciphermode: SymmetricKeyAlgorithm): MessageEncryptionMechanism =
        MessageEncryptionMechanism.aead(ciphermode.algorithmId, this.algorithmId)

    companion object {
        @JvmStatic
        fun fromId(id: Int): AEADAlgorithm? {
            return values().firstOrNull { algorithm -> algorithm.algorithmId == id }
        }

        @JvmStatic
        fun requireFromId(id: Int): AEADAlgorithm {
            return fromId(id) ?: throw NoSuchElementException("No AEADAlgorithm found for id $id")
        }
    }
}
