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
 * [AbstractSignatureBuilder] subclass devoted to build primary-key binding-signatures. Those
 * signatures (also called "back-signatures") are binding signatures issued by signing-capable
 * subkeys.
 */
class PrimaryKeyBindingSignatureBuilder :
    AbstractSignatureBuilder<PrimaryKeyBindingSignatureBuilder> {

    override val signatureTypePredicate: Predicate<SignatureType>
        get() = Predicate<SignatureType> { it == SignatureType.PRIMARYKEY_BINDING }

    @Throws(PGPException::class)
    constructor(
        signingSubkey: PGPSecretKey,
        subkeyProtector: SecretKeyRingProtector
    ) : super(SignatureType.PRIMARYKEY_BINDING, signingSubkey, subkeyProtector)

    @Throws(PGPException::class)
    constructor(
        signingSubkey: PGPSecretKey,
        subkeyProtector: SecretKeyRingProtector,
        hashAlgorithm: HashAlgorithm
    ) : super(
        SignatureType.PRIMARYKEY_BINDING,
        signingSubkey,
        subkeyProtector,
        hashAlgorithm,
        SignatureSubpackets.createHashedSubpackets(signingSubkey.publicKey),
        SignatureSubpackets.createEmptySubpackets())

    val hashedSubpackets: SelfSignatureSubpackets = _hashedSubpackets
    val unhashedSubpackets: SelfSignatureSubpackets = _unhashedSubpackets

    fun applyCallback(callback: SelfSignatureSubpackets.Callback?) = apply {
        callback?.let {
            it.modifyHashedSubpackets(hashedSubpackets)
            it.modifyUnhashedSubpackets(unhashedSubpackets)
        }
    }

    @Throws(PGPException::class)
    fun build(primaryKey: PGPPublicKey): PGPSignature =
        buildAndInitSignatureGenerator().generateCertification(primaryKey, publicSigningKey)
}
