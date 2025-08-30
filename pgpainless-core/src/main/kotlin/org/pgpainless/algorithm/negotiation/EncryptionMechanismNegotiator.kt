// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation

import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.pgpainless.algorithm.AEADAlgorithm
import org.pgpainless.algorithm.AEADCipherMode
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.policy.Policy

fun interface EncryptionMechanismNegotiator {

    fun negotiate(
        policy: Policy,
        override: MessageEncryptionMechanism?,
        features: List<Set<Feature>>,
        aeadAlgorithmPreferences: List<Set<AEADCipherMode>>,
        symmetricAlgorithmPreferences: List<Set<SymmetricKeyAlgorithm>>
    ): MessageEncryptionMechanism

    companion object {
        @JvmStatic
        fun modificationDetectionOrBetter(
            symmetricKeyAlgorithmNegotiator: SymmetricKeyAlgorithmNegotiator
        ): EncryptionMechanismNegotiator =
            object : EncryptionMechanismNegotiator {

                override fun negotiate(
                    policy: Policy,
                    override: MessageEncryptionMechanism?,
                    features: List<Set<Feature>>,
                    aeadAlgorithmPreferences: List<Set<AEADCipherMode>>,
                    symmetricAlgorithmPreferences: List<Set<SymmetricKeyAlgorithm>>
                ): MessageEncryptionMechanism {

                    // If the user supplied an override, use that
                    if (override != null) {
                        return override
                    }

                    // If all support SEIPD2, use SEIPD2
                    if (features.all { it.contains(Feature.MODIFICATION_DETECTION_2) }) {
                        // Find best supported algorithm combination
                        val counted = mutableMapOf<AEADCipherMode, Int>()
                        for (pref in aeadAlgorithmPreferences) {
                            for (mode in pref) {
                                counted[mode] = counted.getOrDefault(mode, 0) + 1
                            }
                        }
                        // filter for supported combinations and find most widely supported
                        val bestSupportedMode: AEADCipherMode =
                            counted
                                .filter {
                                    policy.messageEncryptionAlgorithmPolicy.isAcceptable(
                                        MessageEncryptionMechanism.aead(
                                            it.key.ciphermode.algorithmId,
                                            it.key.aeadAlgorithm.algorithmId))
                                }
                                .maxByOrNull { it.value }
                                ?.key
                                ?: AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_128)

                        // return best supported mode or symmetric key fallback mechanism
                        return MessageEncryptionMechanism.aead(
                            bestSupportedMode.ciphermode.algorithmId,
                            bestSupportedMode.aeadAlgorithm.algorithmId)
                    } else if (features.all { it.contains(Feature.LIBREPGP_OCB_ENCRYPTED_DATA) }) {
                        return MessageEncryptionMechanism.librePgp(
                            symmetricKeyAlgorithmNegotiator
                                .negotiate(
                                    policy.messageEncryptionAlgorithmPolicy
                                        .symmetricAlgorithmPolicy,
                                    null,
                                    symmetricAlgorithmPreferences)
                                .algorithmId)
                    }
                    // If all support SEIPD1, negotiate SEIPD1 using symmetricKeyAlgorithmNegotiator
                    else if (features.all { it.contains(Feature.MODIFICATION_DETECTION) }) {
                        return MessageEncryptionMechanism.integrityProtected(
                            symmetricKeyAlgorithmNegotiator
                                .negotiate(
                                    policy.messageEncryptionAlgorithmPolicy
                                        .symmetricAlgorithmPolicy,
                                    null,
                                    symmetricAlgorithmPreferences)
                                .algorithmId)
                    }
                    // Else fall back to fallback mechanism from policy
                    else {
                        return policy.messageEncryptionAlgorithmPolicy.asymmetricFallbackMechanism
                    }
                }
            }
    }
}
