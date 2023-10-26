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

/** Return true, if this [PGPKeyRing] contains the subkey identified by the [SubkeyIdentifier]. */
fun PGPKeyRing.matches(subkeyIdentifier: SubkeyIdentifier): Boolean =
    this.publicKey.keyID == subkeyIdentifier.primaryKeyId &&
        this.getPublicKey(subkeyIdentifier.subkeyId) != null

/**
 * Return true, if the [PGPKeyRing] contains a public key with the given key-ID.
 *
 * @param keyId keyId
 * @return true if key with the given key-ID is present, false otherwise
 */
fun PGPKeyRing.hasPublicKey(keyId: Long): Boolean = this.getPublicKey(keyId) != null

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
    getPublicKey(keyId)
        ?: throw NoSuchElementException(
            "OpenPGP key does not contain key with id ${keyId.openPgpKeyId()}.")

fun PGPKeyRing.requirePublicKey(fingerprint: OpenPgpFingerprint): PGPPublicKey =
    getPublicKey(fingerprint)
        ?: throw NoSuchElementException(
            "OpenPGP key does not contain key with fingerprint $fingerprint.")

/**
 * Return the [PGPPublicKey] that matches the [OpenPgpFingerprint] of the given [PGPSignature]. If
 * the [PGPSignature] does not carry an issuer-fingerprint subpacket, fall back to the issuer-keyID
 * subpacket to identify the [PGPPublicKey] via its key-ID.
 */
fun PGPKeyRing.getPublicKeyFor(signature: PGPSignature): PGPPublicKey? =
    signature.fingerprint?.let { this.getPublicKey(it) } ?: this.getPublicKey(signature.keyID)

/** Return the [PGPPublicKey] that matches the key-ID of the given [PGPOnePassSignature] packet. */
fun PGPKeyRing.getPublicKeyFor(onePassSignature: PGPOnePassSignature): PGPPublicKey? =
    this.getPublicKey(onePassSignature.keyID)

/** Return the [OpenPgpFingerprint] of this OpenPGP key. */
val PGPKeyRing.openPgpFingerprint: OpenPgpFingerprint
    get() = OpenPgpFingerprint.of(this)

/** Return this OpenPGP key as an ASCII armored String. */
fun PGPKeyRing.toAsciiArmor(): String = PGPainless.asciiArmor(this)
