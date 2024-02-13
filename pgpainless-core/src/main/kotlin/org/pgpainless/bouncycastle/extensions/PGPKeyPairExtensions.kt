// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.PublicSubkeyPacket
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.implementation.ImplementationFactory

fun PGPKeyPair.toPrimaryKeyFormat(): PGPKeyPair {
    val fpCalc = ImplementationFactory.getInstance().keyFingerprintCalculator
    val subkey =
        PublicKeyPacket(publicKey.algorithm, publicKey.creationTime, publicKey.publicKeyPacket.key)
    return PGPKeyPair(
        PGPPublicKey(subkey, fpCalc),
        PGPPrivateKey(publicKey.keyID, subkey, privateKey.privateKeyDataPacket))
}

fun PGPKeyPair.toSubkeyFormat(): PGPKeyPair {
    val fpCalc = ImplementationFactory.getInstance().keyFingerprintCalculator
    // form subkey packet
    val subkey =
        PublicSubkeyPacket(
            publicKey.algorithm, publicKey.creationTime, publicKey.publicKeyPacket.key)
    return PGPKeyPair(
        PGPPublicKey(subkey, fpCalc),
        PGPPrivateKey(publicKey.keyID, subkey, privateKey.privateKeyDataPacket))
}

fun PGPKeyPair.plusCertification(userId: CharSequence, certification: PGPSignature): PGPKeyPair =
    PGPKeyPair(
        PGPPublicKey.addCertification(publicKey, userId.toString(), certification), privateKey)

fun PGPKeyPair.plusCertification(
    userAttribute: PGPUserAttributeSubpacketVector,
    certification: PGPSignature
): PGPKeyPair =
    PGPKeyPair(PGPPublicKey.addCertification(publicKey, userAttribute, certification), privateKey)

fun PGPKeyPair.plusCertification(certification: PGPSignature): PGPKeyPair =
    PGPKeyPair(PGPPublicKey.addCertification(publicKey, certification), privateKey)
