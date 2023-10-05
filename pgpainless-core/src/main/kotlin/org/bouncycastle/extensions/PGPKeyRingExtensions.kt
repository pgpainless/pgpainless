// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.SubkeyIdentifier
import java.util.*
import kotlin.NoSuchElementException
import kotlin.math.max
import kotlin.reflect.KProperty

val PGPKeyRing.primaryPublicKey: PGPPublicKey
    get() = requireNotNull(publicKey).also { require(it.isMasterKey) }

/**
 * Return true, if this [PGPKeyRing] contains the subkey identified by the [SubkeyIdentifier].
 */
fun PGPKeyRing.matches(subkeyIdentifier: SubkeyIdentifier): Boolean =
        this.publicKey.keyID == subkeyIdentifier.primaryKeyId &&
                this.getPublicKey(subkeyIdentifier.subkeyId) != null

/**
 * Return true, if the [PGPKeyRing] contains a public key with the given key-ID.
 *
 * @param keyId keyId
 * @return true if key with the given key-ID is present, false otherwise
 */
fun PGPKeyRing.hasPublicKey(keyId: Long): Boolean =
        this.getPublicKey(keyId) != null

/**
 * Return true, if the [PGPKeyRing] contains a public key with the given fingerprint.
 *
 * @param fingerprint fingerprint
 * @return true if key with the given fingerprint is present, false otherwise
 */
fun PGPKeyRing.hasPublicKey(fingerprint: OpenPgpFingerprint): Boolean =
        this.getPublicKey(fingerprint) != null

/**
 * Return the [PGPPublicKey] with the given [OpenPgpFingerprint] or null, if no such key is present.
 *
 * @param fingerprint fingerprint
 * @return public key
 */
fun PGPKeyRing.getPublicKey(fingerprint: OpenPgpFingerprint): PGPPublicKey? =
        this.getPublicKey(fingerprint.bytes)

fun PGPKeyRing.requirePublicKey(keyId: Long): PGPPublicKey =
        getPublicKey(keyId) ?: throw NoSuchElementException("OpenPGP key does not contain key with id ${keyId.openPgpKeyId()}.")

fun PGPKeyRing.requirePublicKey(fingerprint: OpenPgpFingerprint): PGPPublicKey =
        getPublicKey(fingerprint) ?: throw NoSuchElementException("OpenPGP key does not contain key with fingerprint $fingerprint.")

/**
 * Return the [PGPPublicKey] that matches the [OpenPgpFingerprint] of the given [PGPSignature].
 * If the [PGPSignature] does not carry an issuer-fingerprint subpacket, fall back to the issuer-keyID subpacket to
 * identify the [PGPPublicKey] via its key-ID.
 */
fun PGPKeyRing.getPublicKeyFor(signature: PGPSignature): PGPPublicKey? =
        signature.fingerprint?.let { this.getPublicKey(it) } ?:
        this.getPublicKey(signature.keyID)

/**
 * Return the [PGPPublicKey] that matches the key-ID of the given [PGPOnePassSignature] packet.
 */
fun PGPKeyRing.getPublicKeyFor(onePassSignature: PGPOnePassSignature): PGPPublicKey? =
        this.getPublicKey(onePassSignature.keyID)

/**
 * Return the [OpenPgpFingerprint] of this OpenPGP key.
 */
val PGPKeyRing.openPgpFingerprint: OpenPgpFingerprint
    get() = OpenPgpFingerprint.of(primaryPublicKey)

/**
 * Return this OpenPGP key as an ASCII armored String.
 */
fun PGPKeyRing.toAsciiArmor(): String = PGPainless.asciiArmor(this)

val PGPKeyRing.goodDirectKeySignatures: List<PGPSignature> by LazyPGPKeyRing {
    it.primaryPublicKey.goodDirectKeySignatures
}

val PGPKeyRing.goodDirectKeySignature: PGPSignature? by LazyPGPKeyRing {
    it.primaryPublicKey.goodDirectKeySignature
}

val PGPKeyRing.expirationDate: Date? by LazyPGPKeyRing {
    val dkExp = it.goodDirectKeySignature?.getKeyExpirationDate(it.primaryPublicKey.creationTime)
    val puExp = it.primaryPublicKey.goodUserIds[it.primaryPublicKey.primaryUserId]
                    ?.getKeyExpirationDate(it.primaryPublicKey.creationTime)

    dkExp ?: return@LazyPGPKeyRing puExp // direct-key exp null ? -> userId exp
    puExp ?: return@LazyPGPKeyRing dkExp // userId exp null ? -> direct-key exp

    return@LazyPGPKeyRing if (dkExp < puExp) dkExp else puExp // max direct-key exp, userId exp
}


internal class LazyPGPKeyRing<T>(val function: (PGPKeyRing) -> T) {
    private var value: Result<T>? = null

    operator fun getValue(keys: PGPKeyRing, property: KProperty<*>): T {
        if (value == null) {
            value = try {
                Result.success(function(keys))
            } catch (e : Throwable) {
                Result.failure(e)
            }
        }
        return value!!.getOrThrow()
    }
}