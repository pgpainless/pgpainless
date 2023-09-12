// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.openpgp.*
import org.pgpainless.key.OpenPgpFingerprint

/**
 * OpenPGP certificate containing the public keys of this OpenPGP key.
 */
val PGPSecretKeyRing.certificate: PGPPublicKeyRing
    get() = PGPPublicKeyRing(this.publicKeys.asSequence().toList())

/**
 * Return true, if the [PGPSecretKeyRing] contains a [PGPSecretKey] with the given key-ID.
 *
 * @param keyId keyId of the secret key
 * @return true, if the [PGPSecretKeyRing] has a matching [PGPSecretKey], false otherwise
 */
fun PGPSecretKeyRing.hasSecretKey(keyId: Long): Boolean =
        this.getSecretKey(keyId) != null

/**
 * Return true, if the [PGPSecretKeyRing] contains a [PGPSecretKey] with the given fingerprint.
 *
 * @param fingerprint fingerprint
 * @return true, if the [PGPSecretKeyRing] has a matching [PGPSecretKey], false otherwise
 */
fun PGPSecretKeyRing.hasSecretKey(fingerprint: OpenPgpFingerprint): Boolean =
        this.getSecretKey(fingerprint) != null

/**
 * Return the [PGPSecretKey] with the given [OpenPgpFingerprint].
 *
 * @param fingerprint fingerprint of the secret key
 * @return the secret key or null
 */
fun PGPSecretKeyRing.getSecretKey(fingerprint: OpenPgpFingerprint): PGPSecretKey? =
        this.getSecretKey(fingerprint.bytes)

/**
 * Return the [PGPSecretKey] that matches the [OpenPgpFingerprint] of the given [PGPSignature].
 * If the [PGPSignature] does not carry an issuer-fingerprint subpacket, fall back to the issuer-keyID subpacket to
 * identify the [PGPSecretKey] via its key-ID.
 */
fun PGPSecretKeyRing.getSecretKeyFor(signature: PGPSignature): PGPSecretKey? =
        signature.getFingerprint()?.let { this.getSecretKey(it) } ?:
        this.getSecretKey(signature.keyID)

/**
 * Return the [PGPSecretKey] that matches the key-ID of the given [PGPOnePassSignature] packet.
 */
fun PGPSecretKeyRing.getSecretKeyFor(onePassSignature: PGPOnePassSignature): PGPSecretKey? =
        this.getSecretKey(onePassSignature.keyID)