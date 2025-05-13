// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import java.util.*
import openpgp.formatUTC
import openpgp.plusSeconds
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.RevocationState
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.util.RevocationAttributes.Reason
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil

/**
 * Return the value of the KeyExpirationDate subpacket, or null, if the signature does not carry
 * such a subpacket.
 */
fun PGPSignature.getKeyExpirationDate(keyCreationDate: Date): Date? =
    SignatureSubpacketsUtil.getKeyExpirationTime(this)?.let { keyCreationDate.plusSeconds(it.time) }

/**
 * Return the value of the signature ExpirationTime subpacket, or null, if the signature does not
 * carry such a subpacket.
 */
val PGPSignature.signatureExpirationDate: Date?
    get() =
        SignatureSubpacketsUtil.getSignatureExpirationTime(this)?.let {
            this.creationTime.plusSeconds(it.time)
        }

/** Return true, if the signature is expired at the given reference time. */
fun PGPSignature.isExpired(referenceTime: Date = Date()) =
    signatureExpirationDate?.let { referenceTime >= it } ?: false

/**
 * Return the key-ID of the issuer, determined by examining the IssuerKeyId and IssuerFingerprint
 * subpackets of the signature.
 */
val PGPSignature.issuerKeyId: Long
    get() =
        when (version) {
            2,
            3 -> keyID
            else -> {
                SignatureSubpacketsUtil.getIssuerKeyIdAsLong(this)?.let {
                    if (it != 0L) it else null
                }
                    ?: fingerprint?.keyId ?: 0L
            }
        }

/**
 * Return true, if the signature was likely issued by a key with the given fingerprint.
 *
 * @param fingerprint fingerprint of the key
 * @return true if signature was likely issued by the key
 */
fun PGPSignature.wasIssuedBy(fingerprint: OpenPgpFingerprint): Boolean =
    wasIssuedBy(fingerprint.keyIdentifier)

/**
 * Return true, if the signature was likely issued by the given key.
 *
 * @param key key
 * @return true if signature was likely issued by the key
 */
fun PGPSignature.wasIssuedBy(key: PGPPublicKey): Boolean = wasIssuedBy(key.keyIdentifier)

/**
 * Return true, if the signature was likely issued by a key with the given identifier.
 *
 * @param keyIdentifier key identifier
 * @return true if signature was likely issued by the key
 */
fun PGPSignature.wasIssuedBy(keyIdentifier: KeyIdentifier): Boolean =
    KeyIdentifier.matches(this.keyIdentifiers, keyIdentifier, true)

/** Return true, if this signature is a hard revocation. */
val PGPSignature.isHardRevocation
    get() =
        when (SignatureType.fromCode(signatureType)) {
            null -> false
            SignatureType.KEY_REVOCATION,
            SignatureType.SUBKEY_REVOCATION,
            SignatureType.CERTIFICATION_REVOCATION -> {
                SignatureSubpacketsUtil.getRevocationReason(this)?.let {
                    Reason.isHardRevocation(it.revocationReason)
                }
                    ?: true // no reason -> hard revocation
            }
            else -> false // Not a revocation
        }

/**
 * Assert that the signatures creation time falls into the period between [notBefore] and
 * [notAfter].
 *
 * @param notBefore lower bound. If null, do not check the lower bound
 * @param notAfter upper bound. If null, do not check the upper bound
 */
fun PGPSignature.assertCreatedInBounds(notBefore: Date?, notAfter: Date?) {
    if (notBefore != null && creationTime < notBefore) {
        throw SignatureValidationException(
            "Signature was made before the earliest allowed signature creation time." +
                " Created: ${creationTime.formatUTC()}," +
                " earliest allowed: ${notBefore.formatUTC()}")
    }
    if (notAfter != null && creationTime > notAfter) {
        throw SignatureValidationException(
            "Signature was made after the latest allowed signature creation time." +
                " Created: ${creationTime.formatUTC()}," +
                " latest allowed: ${notAfter.formatUTC()}")
    }
}

/**
 * Deduce a [RevocationState] from the signature. Non-revocation signatures result in
 * [RevocationState.notRevoked]. Hard revocations result in [RevocationState.hardRevoked], while
 * soft revocations return [RevocationState.softRevoked]
 *
 * @return revocation state
 */
fun PGPSignature?.toRevocationState() =
    if (this == null) RevocationState.notRevoked()
    else if (isHardRevocation) RevocationState.hardRevoked()
    else RevocationState.softRevoked(creationTime)

/** The signatures issuer fingerprint as [OpenPgpFingerprint]. */
val PGPSignature.fingerprint: OpenPgpFingerprint?
    get() = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(this)

/** The signatures [PublicKeyAlgorithm]. */
val PGPSignature.publicKeyAlgorithm: PublicKeyAlgorithm
    get() = PublicKeyAlgorithm.requireFromId(keyAlgorithm)

/** The signatures [HashAlgorithm]. */
val PGPSignature.signatureHashAlgorithm: HashAlgorithm
    get() = HashAlgorithm.requireFromId(hashAlgorithm)

/**
 * Return true if the signature has the given [SignatureType].
 *
 * @param type signature type
 * @return true if the signature type matches the signatures type
 */
fun PGPSignature.isOfType(type: SignatureType): Boolean =
    SignatureType.fromCode(signatureType) == type
