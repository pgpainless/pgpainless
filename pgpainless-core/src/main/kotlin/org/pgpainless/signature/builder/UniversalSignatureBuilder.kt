// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder

import java.util.function.Predicate
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.SignatureSubpackets

/**
 * Signature builder without restrictions on subpacket contents. Instead of providing a "build"
 * method, this builder offers the user to decide on their own, how to generate the signature by
 * exposing the [PGPSignatureGenerator] via [signatureGenerator].
 */
class UniversalSignatureBuilder : AbstractSignatureBuilder<UniversalSignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() = Predicate<SignatureType> { true }

    @Throws(PGPException::class)
    constructor(
        signatureType: SignatureType,
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector
    ) : super(signatureType, signingKey, protector)

    @Throws(PGPException::class)
    constructor(
        signingKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        archetypeSignature: PGPSignature
    ) : super(signingKey, protector, archetypeSignature)

    val hashedSubpackets: SignatureSubpackets = _hashedSubpackets
    val unhashedSubpackets: SignatureSubpackets = _unhashedSubpackets

    fun applyCallback(callback: SignatureSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    val signatureGenerator: PGPSignatureGenerator
        @Throws(PGPException::class) get() = buildAndInitSignatureGenerator()
}
