// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import org.bouncycastle.bcpg.sig.*
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.pgpainless.algorithm.*
import org.pgpainless.key.util.RevocationAttributes

class SignatureSubpacketsHelper {

    companion object {
        @JvmStatic
        fun applyFrom(vector: PGPSignatureSubpacketVector, subpackets: SignatureSubpackets) =
            subpackets.apply {
                for (subpacket in vector.toArray()) {
                    val type = SignatureSubpacket.fromCode(subpacket.type)
                    when (type) {
                        SignatureSubpacket.signatureCreationTime,
                        SignatureSubpacket.issuerKeyId,
                        SignatureSubpacket.issuerFingerprint -> {
                            /* ignore, we override this anyway */
                        }
                        SignatureSubpacket.signatureExpirationTime ->
                            (subpacket as SignatureExpirationTime).let {
                                subpackets.setSignatureExpirationTime(it.isCritical, it.time)
                            }
                        SignatureSubpacket.exportableCertification ->
                            (subpacket as Exportable).let {
                                subpackets.setExportable(it.isCritical, it.isExportable)
                            }
                        SignatureSubpacket.trustSignature ->
                            (subpacket as TrustSignature).let {
                                subpackets.setTrust(it.isCritical, it.depth, it.trustAmount)
                            }
                        SignatureSubpacket.revocable ->
                            (subpacket as Revocable).let {
                                subpackets.setRevocable(it.isCritical, it.isRevocable)
                            }
                        SignatureSubpacket.keyExpirationTime ->
                            (subpacket as KeyExpirationTime).let {
                                subpackets.setKeyExpirationTime(it.isCritical, it.time)
                            }
                        SignatureSubpacket.preferredSymmetricAlgorithms ->
                            (subpacket as PreferredAlgorithms).let {
                                subpackets.setPreferredSymmetricKeyAlgorithms(
                                    PreferredAlgorithms(
                                        it.type, it.isCritical, it.isLongLength, it.data))
                            }
                        SignatureSubpacket.preferredHashAlgorithms ->
                            (subpacket as PreferredAlgorithms).let {
                                subpackets.setPreferredHashAlgorithms(
                                    PreferredAlgorithms(
                                        it.type, it.isCritical, it.isLongLength, it.data))
                            }
                        SignatureSubpacket.preferredCompressionAlgorithms ->
                            (subpacket as PreferredAlgorithms).let {
                                subpackets.setPreferredCompressionAlgorithms(
                                    PreferredAlgorithms(
                                        it.type, it.isCritical, it.isLongLength, it.data))
                            }
                        SignatureSubpacket.revocationKey ->
                            (subpacket as RevocationKey).let {
                                subpackets.addRevocationKey(
                                    RevocationKey(
                                        it.isCritical,
                                        it.signatureClass,
                                        it.algorithm,
                                        it.fingerprint))
                            }
                        SignatureSubpacket.notationData ->
                            (subpacket as NotationData).let {
                                subpackets.addNotationData(
                                    it.isCritical,
                                    it.isHumanReadable,
                                    it.notationName,
                                    it.notationValue)
                            }
                        SignatureSubpacket.primaryUserId ->
                            (subpacket as PrimaryUserID).let {
                                subpackets.setPrimaryUserId(
                                    PrimaryUserID(it.isCritical, it.isPrimaryUserID))
                            }
                        SignatureSubpacket.keyFlags ->
                            (subpacket as KeyFlags).let {
                                subpackets.setKeyFlags(
                                    it.isCritical, *(KeyFlag.fromBitmask(it.flags).toTypedArray()))
                            }
                        SignatureSubpacket.signerUserId ->
                            (subpacket as SignerUserID).let {
                                subpackets.setSignerUserId(it.isCritical, it.id)
                            }
                        SignatureSubpacket.revocationReason ->
                            (subpacket as RevocationReason).let {
                                subpackets.setRevocationReason(
                                    it.isCritical,
                                    RevocationAttributes.Reason.fromCode(it.revocationReason),
                                    it.revocationDescription)
                            }
                        SignatureSubpacket.features ->
                            (subpacket as Features).let {
                                subpackets.setFeatures(
                                    it.isCritical,
                                    *(Feature.fromBitmask(it.features.toInt()).toTypedArray()))
                            }
                        SignatureSubpacket.signatureTarget ->
                            (subpacket as SignatureTarget).let {
                                subpackets.setSignatureTarget(
                                    it.isCritical,
                                    PublicKeyAlgorithm.requireFromId(it.publicKeyAlgorithm),
                                    HashAlgorithm.requireFromId(it.hashAlgorithm),
                                    it.hashData)
                            }
                        SignatureSubpacket.embeddedSignature ->
                            (subpacket as EmbeddedSignature).let {
                                subpackets.addEmbeddedSignature(it)
                            }
                        SignatureSubpacket.intendedRecipientFingerprint ->
                            (subpacket as IntendedRecipientFingerprint).let {
                                subpackets.addIntendedRecipientFingerprint(it)
                            }
                        SignatureSubpacket.policyUrl ->
                            (subpacket as PolicyURI).let { subpackets.setPolicyUrl(it) }
                        SignatureSubpacket.regularExpression ->
                            (subpacket as RegularExpression).let {
                                subpackets.setRegularExpression(it)
                            }
                        SignatureSubpacket.keyServerPreferences,
                        SignatureSubpacket.preferredKeyServers,
                        SignatureSubpacket.placeholder,
                        SignatureSubpacket.preferredAEADAlgorithms,
                        SignatureSubpacket.attestedCertification ->
                            subpackets.addResidualSubpacket(subpacket)
                        else -> subpackets.addResidualSubpacket(subpacket)
                    }
                }
            }

        @JvmStatic
        fun applyTo(
            subpackets: SignatureSubpackets,
            generator: PGPSignatureSubpacketGenerator
        ): PGPSignatureSubpacketGenerator {
            return generator.apply {
                addSubpacket(subpackets.issuerKeyIdSubpacket)
                addSubpacket(subpackets.issuerFingerprintSubpacket)
                addSubpacket(subpackets.signatureCreationTimeSubpacket)
                addSubpacket(subpackets.signatureExpirationTimeSubpacket)
                addSubpacket(subpackets.exportableSubpacket)
                addSubpacket(subpackets.policyURISubpacket)
                addSubpacket(subpackets.regularExpressionSubpacket)
                for (notation in subpackets.notationDataSubpackets) {
                    addSubpacket(notation)
                }
                for (recipient in subpackets.intendedRecipientFingerprintSubpackets) {
                    addSubpacket(recipient)
                }
                for (revocationKey in subpackets.revocationKeySubpackets) {
                    addSubpacket(revocationKey)
                }
                addSubpacket(subpackets.signatureTargetSubpacket)
                addSubpacket(subpackets.featuresSubpacket)
                addSubpacket(subpackets.keyFlagsSubpacket)
                addSubpacket(subpackets.trustSubpacket)
                addSubpacket(subpackets.preferredCompressionAlgorithmsSubpacket)
                addSubpacket(subpackets.preferredSymmetricKeyAlgorithmsSubpacket)
                addSubpacket(subpackets.preferredHashAlgorithmsSubpacket)
                for (embedded in subpackets.embeddedSignatureSubpackets) {
                    addSubpacket(embedded)
                }
                addSubpacket(subpackets.signerUserIdSubpacket)
                addSubpacket(subpackets.keyExpirationTimeSubpacket)
                addSubpacket(subpackets.primaryUserIdSubpacket)
                addSubpacket(subpackets.revocableSubpacket)
                addSubpacket(subpackets.revocationReasonSubpacket)
                for (residual in subpackets.residualSubpackets) {
                    addSubpacket(residual)
                }
            }
        }

        @JvmStatic
        private fun PGPSignatureSubpacketGenerator.addSubpacket(
            subpacket: org.bouncycastle.bcpg.SignatureSubpacket?
        ) {
            if (subpacket != null) {
                this.addCustomSubpacket(subpacket)
            }
        }

        @JvmStatic
        fun toVector(subpackets: SignatureSubpackets): PGPSignatureSubpacketVector {
            return PGPSignatureSubpacketGenerator().let {
                applyTo(subpackets, it)
                it.generate()
            }
        }

        @JvmStatic
        fun toVector(subpackets: RevocationSignatureSubpackets): PGPSignatureSubpacketVector {
            return PGPSignatureSubpacketGenerator().let {
                applyTo(subpackets as SignatureSubpackets, it)
                it.generate()
            }
        }
    }
}
