// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentSignature
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

/**
 * [AbstractSignatureBuilder] devoted to direct-key self-signatures. Direct-key self-signatures are
 * calculated by a primary-key over itself.
 */
class DirectKeySelfSignatureBuilder : AbstractSignatureBuilder<DirectKeySelfSignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() = Predicate { it == SignatureType.DIRECT_KEY }

    @Throws(PGPException::class)
    constructor(
        signingKeyRing: PGPSecretKeyRing,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature
    ) : this(
        PGPainless.getInstance().toKey(signingKeyRing).primarySecretKey,
        protector,
        archetypeSignature)

    @Throws(PGPException::class)
    constructor(
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature
    ) : super(signingKey, protector, archetypeSignature)

    @Throws(PGPException::class)
    constructor(
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(SignatureType.DIRECT_KEY, signingKey, protector)

    val hashedSubpackets: SelfSignatureSubpackets = _hashedSubpackets
    val unhashedSubpackets: SelfSignatureSubpackets = _unhashedSubpackets

    fun applyCallback(callback: SelfSignatureSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    @Throws(PGPException::class)
    fun build(): OpenPGPSignature =
        buildAndInitSignatureGenerator()
            .generateCertification(signingKey.publicKey.pgpPublicKey)
            .let { OpenPGPComponentSignature(it, signingKey.publicKey, signingKey.publicKey) }
}
