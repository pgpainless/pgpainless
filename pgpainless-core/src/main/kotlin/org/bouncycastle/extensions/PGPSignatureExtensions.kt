// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import java.util.*
import openpgp.plusSeconds
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.RevocationState
import org.pgpainless.algorithm.SignatureType
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

/** Return true, if the signature was likely issued by a key with the given fingerprint. */
fun PGPSignature.wasIssuedBy(fingerprint: OpenPgpFingerprint): Boolean =
    this.fingerprint?.let { it.keyId == fingerprint.keyId } ?: (keyID == fingerprint.keyId)

/**
 * Return true, if the signature was likely issued by a key with the given fingerprint.
 *
 * @param fingerprint fingerprint bytes
 */
@Deprecated("Discouraged in favor of method taking an OpenPgpFingerprint.")
fun PGPSignature.wasIssuedBy(fingerprint: ByteArray): Boolean =
    try {
        wasIssuedBy(OpenPgpFingerprint.parseFromBinary(fingerprint))
    } catch (e: IllegalArgumentException) {
        // Unknown fingerprint length / format
        false
    }

fun PGPSignature.wasIssuedBy(key: PGPPublicKey): Boolean = wasIssuedBy(OpenPgpFingerprint.of(key))

/** Return true, if this signature is a hard revocation. */
val PGPSignature.isHardRevocation
    get() =
        when (SignatureType.requireFromCode(signatureType)) {
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

fun PGPSignature?.toRevocationState() =
    if (this == null) RevocationState.notRevoked()
    else if (isHardRevocation) RevocationState.hardRevoked()
    else RevocationState.softRevoked(creationTime)

val PGPSignature.fingerprint: OpenPgpFingerprint?
    get() = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(this)

val PGPSignature.publicKeyAlgorithm: PublicKeyAlgorithm
    get() = PublicKeyAlgorithm.requireFromId(keyAlgorithm)

val PGPSignature.signatureHashAlgorithm: HashAlgorithm
    get() = HashAlgorithm.requireFromId(hashAlgorithm)

fun PGPSignature.isOfType(type: SignatureType): Boolean =
    SignatureType.requireFromCode(signatureType) == type
