// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.signature.SignatureUtils
import java.util.*

fun PGPSignature.getKeyExpirationDate(keyCreationDate: Date): Date? =
        SignatureUtils.getKeyExpirationDate(keyCreationDate, this)

fun PGPSignature.getSignatureExpirationDate(): Date? =
        SignatureUtils.getSignatureExpirationDate(this)

fun PGPSignature.isExpired(referenceTime: Date = Date()) =
        SignatureUtils.isSignatureExpired(this, referenceTime)

fun PGPSignature.getIssuerKeyId() = SignatureUtils.determineIssuerKeyId(this)

fun PGPSignature.wasIssuedBy(fingerprint: OpenPgpFingerprint) = SignatureUtils.wasIssuedBy(fingerprint, this)
