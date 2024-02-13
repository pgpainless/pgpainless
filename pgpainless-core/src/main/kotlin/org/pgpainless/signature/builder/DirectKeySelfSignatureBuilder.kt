// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpackets

/**
 * [AbstractSignatureBuilder] devoted to direct-key self-signatures. Direct-key self-signatures are
 * calculated by a primary-key over itself.
 */
class DirectKeySelfSignatureBuilder : AbstractSignatureBuilder<DirectKeySelfSignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() = Predicate { it == SignatureType.DIRECT_KEY }

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature
    ) : super(signingKey, protector, archetypeSignature)

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPKeyPair,
        hashAlgorithm: HashAlgorithm
    ) : this(signingKey.privateKey, signingKey.publicKey, hashAlgorithm)

    @Throws(PGPException::class)
    constructor(
        privateSigningKey: PGPPrivateKey,
        publicSigningKey: PGPPublicKey,
        hashAlgorithm: HashAlgorithm
    ) : super(
        privateSigningKey,
        publicSigningKey,
        hashAlgorithm,
        SignatureType.DIRECT_KEY,
        SignatureSubpackets.createHashedSubpackets(publicSigningKey),
        SignatureSubpackets.createEmptySubpackets())

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
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
    fun build(): PGPSignature =
        buildAndInitSignatureGenerator().let { it.generateCertification(publicSigningKey) }
}
