// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpackets

/**
 * [AbstractSignatureBuilder] devoted to generating subkey binding signatures. A subkey binding
 * signature is calculated by a primary key over a subkey.
 */
class SubkeyBindingSignatureBuilder : AbstractSignatureBuilder<SubkeyBindingSignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() = Predicate<SignatureType> { it == SignatureType.SUBKEY_BINDING }

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(SignatureType.SUBKEY_BINDING, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector,
        hashAlgorithm: HashAlgorithm
    ) : super(
        SignatureType.SUBKEY_BINDING,
        signingKey,
        protector,
        hashAlgorithm,
        SignatureSubpackets.createHashedSubpackets(signingKey.publicKey),
        SignatureSubpackets.createEmptySubpackets())

    @Throws(PGPException::class)
    constructor(
        signingKey: PGPSecretKey,
        protector: SecretKeyRingProtector,
        oldSubkeyBinding: PGPSignature
    ) : super(
        signingKey,
        protector,
        oldSubkeyBinding.also {
            require(it.signatureType == SignatureType.SUBKEY_BINDING.code) {
                "Invalid signature type."
            }
        })

    val hashedSubpackets: SelfSignatureSubpackets = _hashedSubpackets
    val unhashedSubpackets: SelfSignatureSubpackets = _unhashedSubpackets

    fun applyCallback(callback: SelfSignatureSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    @Throws(PGPException::class)
    fun build(subkey: PGPPublicKey): PGPSignature =
        buildAndInitSignatureGenerator().generateCertification(publicSigningKey, subkey)
}
