// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import openpgp.filterNotNullValues
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.signature.consumer.SignatureVerifier
import java.util.*
import kotlin.reflect.KProperty

/**
 * For secret keys of types [PublicKeyAlgorithm.ECDSA], [PublicKeyAlgorithm.ECDH] and [PublicKeyAlgorithm.EDDSA],
 * this method returns the name of the underlying elliptic curve.
 *
 * For other key types or unknown curves, this method throws an [IllegalArgumentException].
 *
 * @return curve name
 */
fun PGPPublicKey.getCurveName(): String {
    PublicKeyAlgorithm.requireFromId(algorithm)
            .let {
                when (it) {
                    PublicKeyAlgorithm.ECDSA -> publicKeyPacket.key as ECDSAPublicBCPGKey
                    PublicKeyAlgorithm.ECDH -> publicKeyPacket.key as ECDHPublicBCPGKey
                    PublicKeyAlgorithm.EDDSA -> publicKeyPacket.key as EdDSAPublicBCPGKey
                    else -> throw IllegalArgumentException("No an elliptic curve public key ($it).")
                }
            }
            .let { if (it.curveOID == GNUObjectIdentifiers.Ed25519) return EdDSACurve._Ed25519.curveName else it.curveOID}
            .let { it to ECUtil.getCurveName(it) }
            .let { if (it.second != null) return it.second else throw IllegalArgumentException("Unknown curve: ${it.first}") }
}

/**
 * Return the [PublicKeyAlgorithm] of this key.
 */
val PGPPublicKey.publicKeyAlgorithm: PublicKeyAlgorithm
    get() = PublicKeyAlgorithm.requireFromId(algorithm)

/**
 * Return the [OpenPgpFingerprint] of this key.
 */
val PGPPublicKey.openPgpFingerprint: OpenPgpFingerprint by LazyPGPPublicKey { OpenPgpFingerprint.of(it) }

val PGPPublicKey.goodDirectKeySignatures: List<PGPSignature> by LazyPGPPublicKey { key ->
    key.getSignaturesOfType(SignatureType.DIRECT_KEY.code)
            .asSequence()
            .filter { it.keyID == key.keyID }
            .filter {
                runCatching {
                    SignatureVerifier.verifyDirectKeySignature(it, key, PGPainless.getPolicy(), Date())
                }.getOrElse { false }
            }
            .toList()
}

val PGPPublicKey.goodDirectKeySignature: PGPSignature? by LazyPGPPublicKey {
    it.goodDirectKeySignatures
            .sortedBy { sig -> sig.creationTime }
            .lastOrNull()
}

val PGPPublicKey.goodKeyRevocations: List<PGPSignature> by LazyPGPPublicKey { key ->
    key.getSignaturesOfType(SignatureType.KEY_REVOCATION.code)
            .asSequence()
            .filter { it.keyID == key.keyID }
            .filter {
                runCatching {
                    SignatureVerifier.verifyKeyRevocationSignature(it, key, PGPainless.getPolicy(), Date())
                }.getOrElse { false }
            }
            .toList()
}

val PGPPublicKey.goodKeyRevocation: PGPSignature? by LazyPGPPublicKey {
    it.goodKeyRevocations
            .sortedBy { sig -> sig.creationTime }
            .lastOrNull()
}

val PGPPublicKey.goodUserIds: Map<String, PGPSignature> by LazyPGPPublicKey { it.getGoodUserIds(Date()) }

fun PGPPublicKey.getGoodUserIds(referenceTime: Date): Map<String, PGPSignature> {
    return userIDs.asSequence().associateWith { userId ->
        getSignaturesForID(userId).asSequence()
                .filter { it.wasIssuedBy(this) }
                .filter { it.isCertification }
                .filter { it.isEffective(referenceTime)}
                .sortedBy { it.creationTime }
                .lastOrNull()
    }.filterNotNullValues()
}

val PGPPublicKey.primaryUserId: String? by LazyPGPPublicKey { it.getPrimaryUserId(Date()) }

fun PGPPublicKey.getPrimaryUserId(referenceTime: Date): String? =
        getGoodUserIds(referenceTime).entries
                .sortedBy { it.value.creationTime }
                .lastOrNull { it.value.hashedSubPackets.isPrimaryUserID }?.key // latest primary User ID
                ?: getGoodUserIds(referenceTime).keys.firstOrNull() // else first User ID

internal class LazyPGPPublicKey<T>(val function: (PGPPublicKey) -> T) {
    private var value: Result<T>? = null

    operator fun getValue(pgpPublicKey: PGPPublicKey, property: KProperty<*>): T {
        if (value == null) {
            value = try {
                Result.success(function(pgpPublicKey))
            } catch (e : Throwable) {
                Result.failure(e)
            }
        }
        return value!!.getOrThrow()
    }
}
