// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil

abstract class KeyAccessor(protected val info: KeyRingInfo, protected val key: SubkeyIdentifier) {

    /**
     * Depending on the way we address the key (key-id or user-id), return the respective
     * [PGPSignature] which contains the algorithm preferences we are going to use.
     *
     * <p>
     * If we address a key via its user-id, we want to rely on the algorithm preferences in the
     * user-id certification, while we would instead rely on those in the direct-key signature if
     * we'd address the key by key-id.
     *
     * @return signature
     */
    abstract val signatureWithPreferences: PGPSignature

    /** Preferred symmetric key encryption algorithms. */
    val preferredSymmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>
        get() =
            SignatureSubpacketsUtil.parsePreferredSymmetricKeyAlgorithms(signatureWithPreferences)

    /** Preferred hash algorithms. */
    val preferredHashAlgorithms: Set<HashAlgorithm>
        get() = SignatureSubpacketsUtil.parsePreferredHashAlgorithms(signatureWithPreferences)

    /** Preferred compression algorithms. */
    val preferredCompressionAlgorithms: Set<CompressionAlgorithm>
        get() =
            SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(signatureWithPreferences)

    /**
     * Address the key via a user-id (e.g. `Alice <alice@wonderland.lit>`). In this case we are
     * sourcing preferred algorithms from the user-id certification first.
     */
    class ViaUserId(info: KeyRingInfo, key: SubkeyIdentifier, private val userId: CharSequence) :
        KeyAccessor(info, key) {
        override val signatureWithPreferences: PGPSignature
            get() =
                checkNotNull(info.getLatestUserIdCertification(userId.toString())) {
                    "No valid user-id certification signature found for '$userId'."
                }
    }

    /**
     * Address the key via key-id. In this case we are sourcing preferred algorithms from the keys
     * direct-key signature first.
     */
    class ViaKeyId(info: KeyRingInfo, key: SubkeyIdentifier) : KeyAccessor(info, key) {
        override val signatureWithPreferences: PGPSignature
            get() {
                // If the key is located by Key ID, the algorithm of the primary User ID of the key
                // provides the
                // preferred symmetric algorithm.
                info.primaryUserId?.let { userId ->
                    info.getLatestUserIdCertification(userId).let { if (it != null) return it }
                }

                if (info.latestDirectKeySelfSignature != null) {
                    return info.latestDirectKeySelfSignature
                }

                return info.getCurrentSubkeyBindingSignature(key.subkeyId)!!
            }
    }

    class SubKey(info: KeyRingInfo, key: SubkeyIdentifier) : KeyAccessor(info, key) {
        override val signatureWithPreferences: PGPSignature
            get() =
                checkNotNull(
                    if (key.isPrimaryKey) {
                        info.latestDirectKeySelfSignature
                            ?: info.primaryUserId?.let { info.getLatestUserIdCertification(it) }
                    } else {
                        info.getCurrentSubkeyBindingSignature(key.subkeyId)
                    }) {
                        "No valid signature found."
                    }
    }
}
