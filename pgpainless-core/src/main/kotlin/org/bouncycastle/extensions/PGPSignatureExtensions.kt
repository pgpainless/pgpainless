// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.RevocationState
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.signature.SignatureUtils
import java.util.*

/**
 * Return the value of the KeyExpirationDate subpacket, or null, if the signature does not carry
 * such a subpacket.
 */
fun PGPSignature.getKeyExpirationDate(keyCreationDate: Date): Date? =
        SignatureUtils.getKeyExpirationDate(keyCreationDate, this)

/**
 * Return the value of the signature ExpirationTime subpacket, or null, if the signature
 * does not carry such a subpacket.
 */
fun PGPSignature.getSignatureExpirationDate(): Date? =
        SignatureUtils.getSignatureExpirationDate(this)

/**
 * Return true, if the signature is expired at the given reference time.
 */
fun PGPSignature.isExpired(referenceTime: Date = Date()) =
        SignatureUtils.isSignatureExpired(this, referenceTime)

/**
 * Return the key-ID of the issuer, determined by examining the IssuerKeyId and IssuerFingerprint
 * subpackets of the signature.
 */
fun PGPSignature.getIssuerKeyId() = SignatureUtils.determineIssuerKeyId(this)

/**
 * Return true, if the signature was likely issued by the key with the given fingerprint.
 */
fun PGPSignature.wasIssuedBy(fingerprint: OpenPgpFingerprint) = SignatureUtils.wasIssuedBy(fingerprint, this)

/**
 * Return true, if this signature is a hard revocation.
 */
fun PGPSignature.isHardRevocation() = SignatureUtils.isHardRevocation(this)

fun PGPSignature?.toRevocationState() =
        if (this == null) RevocationState.notRevoked()
        else
            if (isHardRevocation()) RevocationState.hardRevoked()
            else RevocationState.softRevoked(creationTime)
