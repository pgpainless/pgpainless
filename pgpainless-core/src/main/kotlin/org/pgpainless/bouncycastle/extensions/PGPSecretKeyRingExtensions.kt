// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.key.OpenPgpFingerprint

/** OpenPGP certificate containing the public keys of this OpenPGP key. */
val PGPSecretKeyRing.certificate: PGPPublicKeyRing
    get() = PGPPublicKeyRing(this.publicKeys.asSequence().toList())

/**
 * Return true, if the [PGPSecretKeyRing] contains a [PGPSecretKey] with the given key-ID.
 *
 * @param keyId keyId of the secret key
 * @return true, if the [PGPSecretKeyRing] has a matching [PGPSecretKey], false otherwise
 */
@Deprecated("Pass in a KeyIdentifier instead.")
fun PGPSecretKeyRing.hasSecretKey(keyId: Long): Boolean = hasSecretKey(KeyIdentifier(keyId))

/**
 * Return true, if the [PGPSecretKeyRing] contains a [PGPSecretKey] with the given [keyIdentifier].
 *
 * @param keyIdentifier identifier of the secret key
 * @return true, if the [PGPSecretKeyRing] has a matching [PGPSecretKey], false otherwise
 */
fun PGPSecretKeyRing.hasSecretKey(keyIdentifier: KeyIdentifier): Boolean =
    this.getSecretKey(keyIdentifier) != null

/**
 * Return true, if the [PGPSecretKeyRing] contains a [PGPSecretKey] with the given fingerprint.
 *
 * @param fingerprint fingerprint
 * @return true, if the [PGPSecretKeyRing] has a matching [PGPSecretKey], false otherwise
 */
fun PGPSecretKeyRing.hasSecretKey(fingerprint: OpenPgpFingerprint): Boolean =
    hasSecretKey(fingerprint.keyIdentifier)

/**
 * Return the [PGPSecretKey] with the given [OpenPgpFingerprint].
 *
 * @param fingerprint fingerprint of the secret key
 * @return the secret key or null
 */
fun PGPSecretKeyRing.getSecretKey(fingerprint: OpenPgpFingerprint): PGPSecretKey? =
    this.getSecretKey(fingerprint.keyIdentifier)

/**
 * Return the [PGPSecretKey] with the given key-ID.
 *
 * @throws NoSuchElementException if the OpenPGP key doesn't contain a secret key with the given
 *   key-ID
 */
@Deprecated("Pass in a KeyIdentifier instead.")
fun PGPSecretKeyRing.requireSecretKey(keyId: Long): PGPSecretKey =
    requireSecretKey(KeyIdentifier(keyId))

/**
 * Return the [PGPSecretKey] with the given [keyIdentifier].
 *
 * @throws NoSuchElementException if the OpenPGP key doesn't contain a secret key with the given
 *   keyIdentifier
 */
fun PGPSecretKeyRing.requireSecretKey(keyIdentifier: KeyIdentifier): PGPSecretKey =
    getSecretKey(keyIdentifier)
        ?: throw NoSuchElementException(
            "OpenPGP key does not contain key with id ${keyIdentifier}.")

/**
 * Return the [PGPSecretKey] with the given fingerprint.
 *
 * @throws NoSuchElementException of the OpenPGP key doesn't contain a secret key with the given
 *   fingerprint
 */
fun PGPSecretKeyRing.requireSecretKey(fingerprint: OpenPgpFingerprint): PGPSecretKey =
    requireSecretKey(fingerprint.keyIdentifier)

/**
 * Return the [PGPSecretKey] that matches the [OpenPgpFingerprint] of the given [PGPSignature]. If
 * the [PGPSignature] does not carry an issuer-fingerprint subpacket, fall back to the issuer-keyID
 * subpacket to identify the [PGPSecretKey] via its key-ID.
 */
fun PGPSecretKeyRing.getSecretKeyFor(signature: PGPSignature): PGPSecretKey? =
    signature.fingerprint?.let { this.getSecretKey(it) } ?: this.getSecretKey(signature.keyID)

/** Return the [PGPSecretKey] that matches the key-ID of the given [PGPOnePassSignature] packet. */
fun PGPSecretKeyRing.getSecretKeyFor(onePassSignature: PGPOnePassSignature): PGPSecretKey? =
    this.getSecretKey(onePassSignature.keyIdentifier)

/**
 * Return the [PGPSecretKey] that can be used to decrypt the given [PGPPublicKeyEncryptedData]
 * packet.
 *
 * @param pkesk public-key encrypted session-key packet
 * @return secret-key or null if no matching secret key was found
 */
fun PGPSecretKeyRing.getSecretKeyFor(pkesk: PGPPublicKeyEncryptedData): PGPSecretKey? =
    this.getSecretKey(pkesk.keyIdentifier)

/**
 * Convert the [PGPSecretKeyRing] into an [OpenPGPKey].
 *
 * @return key
 */
@Deprecated("Use toOpenPGPKey(implementation) instead.")
fun PGPSecretKeyRing.toOpenPGPKey(): OpenPGPKey =
    toOpenPGPKey(PGPainless.getInstance().implementation)

/**
 * Convert the [PGPSecretKeyRing] into an [OpenPGPKey] using the given [OpenPGPImplementation].
 *
 * @param implementation openpgp implementation
 * @return key
 */
fun PGPSecretKeyRing.toOpenPGPKey(implementation: OpenPGPImplementation): OpenPGPKey =
    OpenPGPKey(this, implementation)
