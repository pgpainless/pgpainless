// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets

/** [AbstractSignatureBuilder] subclass devoted to revocation signatures. */
class RevocationSignatureBuilder : AbstractSignatureBuilder<RevocationSignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() =
            Predicate<SignatureType> {
                it in
                    listOf(
                        SignatureType.KEY_REVOCATION,
                        SignatureType.SUBKEY_REVOCATION,
                        SignatureType.CERTIFICATION_REVOCATION)
            }

    @Throws(PGPException::class)
    constructor(
        signatureType: SignatureType,
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(signatureType, signingKey, protector) {
        hashedSubpackets.setRevocable(false)
    }

    val hashedSubpackets: RevocationSignatureSubpackets = _hashedSubpackets
    val unhashedSubpackets: RevocationSignatureSubpackets = _unhashedSubpackets

    fun applyCallback(callback: RevocationSignatureSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    @Throws(PGPException::class)
    fun build(revokeeKey: PGPPublicKey): PGPSignature =
        buildAndInitSignatureGenerator().let {
            if (_signatureType == SignatureType.KEY_REVOCATION) {
                require(revokeeKey.isMasterKey) {
                    "Signature type is KEY_REVOCATION, but provided revokee does not appear to be a primary key."
                }
                it.generateCertification(revokeeKey)
            } else {
                it.generateCertification(publicSigningKey, revokeeKey)
            }
        }

    @Throws(PGPException::class)
    fun build(revokeeUserId: CharSequence): PGPSignature =
        buildAndInitSignatureGenerator()
            .also {
                require(_signatureType == SignatureType.CERTIFICATION_REVOCATION) {
                    "Signature type is != CERTIFICATION_REVOCATION."
                }
            }
            .generateCertification(revokeeUserId.toString(), publicSigningKey)
}
