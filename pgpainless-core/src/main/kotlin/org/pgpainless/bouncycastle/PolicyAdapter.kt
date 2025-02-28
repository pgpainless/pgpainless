// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle

import java.util.Date
import org.bouncycastle.openpgp.api.OpenPGPPolicy
import org.bouncycastle.openpgp.api.OpenPGPPolicy.OpenPGPNotationRegistry
import org.pgpainless.policy.Policy

/** Adapter class that adapts a PGPainless [Policy] object to Bouncy Castles [OpenPGPPolicy]. */
class PolicyAdapter(val policy: Policy = Policy.getInstance()) : OpenPGPPolicy {

    /**
     * Determine, whether the hash algorithm of a document signature is acceptable.
     *
     * @param algorithmId hash algorithm ID
     * @param signatureCreationTime optional signature creation time
     * @return boolean indicating whether the hash algorithm is acceptable
     */
    override fun isAcceptableDocumentSignatureHashAlgorithm(
        algorithmId: Int,
        signatureCreationTime: Date?
    ): Boolean {
        return if (signatureCreationTime == null)
            policy.dataSignatureHashAlgorithmPolicy.isAcceptable(algorithmId)
        else
            policy.dataSignatureHashAlgorithmPolicy.isAcceptable(algorithmId, signatureCreationTime)
    }

    /**
     * Determine, whether the hash algorithm of a revocation signature is acceptable.
     *
     * @param algorithmId hash algorithm ID
     * @param revocationCreationTime optional revocation signature creation time
     * @return boolean indicating whether the hash algorithm is acceptable
     */
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

    /**
     * Determine, whether the hash algorithm of a certification signature is acceptable.
     *
     * @param algorithmId hash algorithm ID
     * @param certificationCreationTime optional certification signature creation time
     * @return boolean indicating whether the hash algorithm is acceptable
     */
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

    /**
     * Return the default hash algorithm for certification signatures. This is used as fallback if
     * not suitable hash algorithm can be negotiated.
     *
     * @return default certification signature hash algorithm
     */
    override fun getDefaultCertificationSignatureHashAlgorithm(): Int {
        return policy.certificationSignatureHashAlgorithmPolicy.defaultHashAlgorithm.algorithmId
    }

    /**
     * Return the default hash algorithm for document signatures. This is used as fallback if not
     * suitable hash algorithm can be negotiated.
     *
     * @return default document signature hash algorithm
     */
    override fun getDefaultDocumentSignatureHashAlgorithm(): Int {
        return policy.dataSignatureHashAlgorithmPolicy.defaultHashAlgorithm.algorithmId
    }

    /**
     * Determine, whether the given symmetric encryption algorithm is acceptable.
     *
     * @param algorithmId symmetric encryption algorithm ID
     * @return boolean indicating, whether the encryption algorithm is acceptable
     */
    override fun isAcceptableSymmetricKeyAlgorithm(algorithmId: Int): Boolean {
        return policy.symmetricKeyEncryptionAlgorithmPolicy.isAcceptable(algorithmId)
    }
    /**
     * Return the default symmetric encryption algorithm. This algorithm is used as fallback to
     * encrypt messages if no suitable symmetric encryption algorithm can be negotiated.
     *
     * @return default symmetric encryption algorithm
     */
    override fun getDefaultSymmetricKeyAlgorithm(): Int {
        return policy.symmetricKeyEncryptionAlgorithmPolicy.defaultSymmetricKeyAlgorithm.algorithmId
    }

    /**
     * Determine, whether the [bitStrength] of an asymmetric public key of the given algorithm is
     * strong enough.
     *
     * @param algorithmId public key algorithm ID
     * @param bitStrength strength of the key in bits
     * @return boolean indicating whether the bit strength is sufficient
     */
    override fun isAcceptablePublicKeyStrength(algorithmId: Int, bitStrength: Int): Boolean {
        return policy.publicKeyAlgorithmPolicy.isAcceptable(algorithmId, bitStrength)
    }

    /**
     * Adapt PGPainless' [org.pgpainless.util.NotationRegistry] to Bouncy Castles
     * [OpenPGPNotationRegistry].
     *
     * @return adapted [OpenPGPNotationRegistry]
     */
    override fun getNotationRegistry(): OpenPGPNotationRegistry {
        return object : OpenPGPNotationRegistry() {

            /** Determine, whether the given [notationName] is known by the registry. */
            override fun isNotationKnown(notationName: String?): Boolean {
                return notationName?.let { policy.notationRegistry.isKnownNotation(it) } ?: false
            }

            /**
             * Add a known notation name to the registry.
             *
             * @param notationName notation name
             */
            override fun addKnownNotation(notationName: String?) {
                notationName?.let { policy.notationRegistry.addKnownNotation(it) }
            }
        }
    }
}
