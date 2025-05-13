// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.pgpainless.PGPainless
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.SubkeyIdentifier

/**
 * Return true, if this [PGPKeyRing] contains the subkey identified by the [SubkeyIdentifier].
 *
 * @param subkeyIdentifier subkey identifier
 * @return true if the [PGPKeyRing] contains the [SubkeyIdentifier]
 */
fun PGPKeyRing.matches(subkeyIdentifier: SubkeyIdentifier): Boolean =
    this.publicKey.keyIdentifier.matches(subkeyIdentifier.certificateIdentifier) &&
        this.getPublicKey(subkeyIdentifier.componentKeyIdentifier) != null

/**
 * Return true, if this [PGPKeyRing] contains the given [componentKey].
 *
 * @param componentKey component key
 * @return true if the [PGPKeyRing] contains the [componentKey]
 */
fun PGPKeyRing.matches(componentKey: OpenPGPComponentKey): Boolean =
    this.matches(SubkeyIdentifier(componentKey))

/**
 * Return true, if the [PGPKeyRing] contains a public key with the given [keyIdentifier].
 *
 * @param keyIdentifier KeyIdentifier
 * @return true if key with the given key-ID is present, false otherwise
 */
fun PGPKeyRing.hasPublicKey(keyIdentifier: KeyIdentifier): Boolean =
    this.getPublicKey(keyIdentifier) != null

/**
 * Return true, if the [PGPKeyRing] contains a public key with the given key-ID.
 *
 * @param keyId keyId
 * @return true if key with the given key-ID is present, false otherwise
 */
@Deprecated("Pass in a KeyIdentifier instead.")
fun PGPKeyRing.hasPublicKey(keyId: Long): Boolean = hasPublicKey(KeyIdentifier(keyId))

/**
 * Return true, if the [PGPKeyRing] contains a public key with the given fingerprint.
 *
 * @param fingerprint fingerprint
 * @return true if key with the given fingerprint is present, false otherwise
 */
fun PGPKeyRing.hasPublicKey(fingerprint: OpenPgpFingerprint): Boolean =
    hasPublicKey(fingerprint.keyIdentifier)

/**
 * Return the [PGPPublicKey] with the given [OpenPgpFingerprint] or null, if no such key is present.
 *
 * @param fingerprint fingerprint
 * @return public key
 */
fun PGPKeyRing.getPublicKey(fingerprint: OpenPgpFingerprint): PGPPublicKey? =
    this.getPublicKey(fingerprint.keyIdentifier)

/**
 * Return the [PGPPublicKey] with the given [keyIdentifier], or throw a [NoSuchElementException] if
 * no matching public key was found.
 *
 * @param keyIdentifier key identifier
 * @return public key
 * @throws NoSuchElementException if no matching public key was found
 */
fun PGPKeyRing.requirePublicKey(keyIdentifier: KeyIdentifier): PGPPublicKey =
    getPublicKey(keyIdentifier)
        ?: throw NoSuchElementException("OpenPGP key does not contain key with id $keyIdentifier.")

/**
 * Return the [PGPPublicKey] with the given key-id, or throw a [NoSuchElementException] if no
 * matching public key was found.
 *
 * @param keyId key id
 * @return public key
 * @throws NoSuchElementException if no matching public key was found
 */
@Deprecated("Pass in a KeyIdentifier instead.")
fun PGPKeyRing.requirePublicKey(keyId: Long): PGPPublicKey = requirePublicKey(KeyIdentifier(keyId))

/**
 * Return the [PGPPublicKey] with the given [fingerprint], or throw a [NoSuchElementException] if no
 * matching public key was found.
 *
 * @param fingerprint key fingerprint
 * @return public key
 * @throws NoSuchElementException if no matching public key was found
 */
fun PGPKeyRing.requirePublicKey(fingerprint: OpenPgpFingerprint): PGPPublicKey =
    requirePublicKey(fingerprint.keyIdentifier)

/**
 * Return the [PGPPublicKey] that matches the [OpenPgpFingerprint] of the given [PGPSignature]. If
 * the [PGPSignature] does not carry an issuer-fingerprint subpacket, fall back to the issuer-keyID
 * subpacket to identify the [PGPPublicKey] via its key-ID.
 */
fun PGPKeyRing.getPublicKeyFor(signature: PGPSignature): PGPPublicKey? =
    signature.fingerprint?.let { this.getPublicKey(it.keyIdentifier) }
        ?: this.getPublicKey(signature.keyID)

/** Return the [PGPPublicKey] that matches the key-ID of the given [PGPOnePassSignature] packet. */
fun PGPKeyRing.getPublicKeyFor(onePassSignature: PGPOnePassSignature): PGPPublicKey? =
    this.getPublicKey(onePassSignature.keyIdentifier)

/** Return the [OpenPgpFingerprint] of this OpenPGP key. */
val PGPKeyRing.openPgpFingerprint: OpenPgpFingerprint
    get() = OpenPgpFingerprint.of(this)

/** Return this OpenPGP key as an ASCII armored String. */
fun PGPKeyRing.toAsciiArmor(): String = PGPainless.asciiArmor(this)

/**
 * Convert the given [PGPKeyRing] into an [OpenPGPCertificate].
 *
 * @return certificate
 */
@Deprecated("Use toOpenPGPCertificate(implementation) instead.")
fun PGPKeyRing.toOpenPGPCertificate(): OpenPGPCertificate =
    toOpenPGPCertificate(PGPainless.getInstance().implementation)

/**
 * Convert the given [PGPKeyRing] into an [OpenPGPCertificate] using the given
 * [OpenPGPImplementation].
 *
 * @param implementation OpenPGP implementation
 * @return certificate
 */
fun PGPKeyRing.toOpenPGPCertificate(implementation: OpenPGPImplementation): OpenPGPCertificate =
    OpenPGPCertificate(this, implementation)
