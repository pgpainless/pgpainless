// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle

import java.util.Date
import org.bouncycastle.openpgp.api.OpenPGPPolicy
import org.bouncycastle.openpgp.api.OpenPGPPolicy.OpenPGPNotationRegistry
import org.pgpainless.policy.Policy

class PolicyAdapter(val policy: Policy = Policy.getInstance()) : OpenPGPPolicy {

    override fun isAcceptableDocumentSignatureHashAlgorithm(
        algorithmId: Int,
        signatureCreationTime: Date?
    ): Boolean {
        return if (signatureCreationTime == null)
            policy.dataSignatureHashAlgorithmPolicy.isAcceptable(algorithmId)
        else
            policy.dataSignatureHashAlgorithmPolicy.isAcceptable(algorithmId, signatureCreationTime)
    }

    override fun isAcceptableRevocationSignatureHashAlgorithm(
        algorithmId: Int,
        revocationCreationTime: Date?
    ): Boolean {
        return if (revocationCreationTime == null)
            policy.revocationSignatureHashAlgorithmPolicy.isAcceptable(algorithmId)
        else
            policy.revocationSignatureHashAlgorithmPolicy.isAcceptable(
                algorithmId, revocationCreationTime)
    }

    override fun isAcceptableCertificationSignatureHashAlgorithm(
        algorithmId: Int,
        certificationCreationTime: Date?
    ): Boolean {
        return if (certificationCreationTime == null)
            policy.certificationSignatureHashAlgorithmPolicy.isAcceptable(algorithmId)
        else
            policy.certificationSignatureHashAlgorithmPolicy.isAcceptable(
                algorithmId, certificationCreationTime)
    }

    override fun getDefaultCertificationSignatureHashAlgorithm(): Int {
        return policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm.algorithmId
    }

    override fun getDefaultDocumentSignatureHashAlgorithm(): Int {
        return policy.dataSignatureHashAlgorithmPolicy.defaultHashAlgorithm.algorithmId
    }

    override fun isAcceptableSymmetricKeyAlgorithm(p0: Int): Boolean {
        return policy.symmetricKeyEncryptionAlgorithmPolicy.isAcceptable(p0)
    }

    override fun getDefaultSymmetricKeyAlgorithm(): Int {
        return policy.symmetricKeyEncryptionAlgorithmPolicy.defaultSymmetricKeyAlgorithm.algorithmId
    }

    override fun isAcceptablePublicKeyStrength(algorithmId: Int, bitStrength: Int): Boolean {
        return policy.publicKeyAlgorithmPolicy.isAcceptable(algorithmId, bitStrength)
    }

    override fun getNotationRegistry(): OpenPGPPolicy.OpenPGPNotationRegistry {
        return object : OpenPGPNotationRegistry() {
            override fun isNotationKnown(notationName: String?): Boolean {
                return notationName?.let { policy.notationRegistry.isKnownNotation(it) } ?: false
            }

            override fun addKnownNotation(notationName: String?) {
                notationName?.let { policy.notationRegistry.addKnownNotation(it) }
            }
        }
    }
}
