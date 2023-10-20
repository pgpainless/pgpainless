// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import org.bouncycastle.bcpg.sig.RevocationReason
import org.pgpainless.key.util.RevocationAttributes

interface RevocationSignatureSubpackets : BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<RevocationSignatureSubpackets>

    fun setRevocationReason(revocationAttributes: RevocationAttributes): RevocationSignatureSubpackets

    fun setRevocationReason(isCritical: Boolean, revocationAttributes: RevocationAttributes): RevocationSignatureSubpackets

    fun setRevocationReason(isCritical: Boolean, reason: RevocationAttributes.Reason, description: CharSequence): RevocationSignatureSubpackets

    fun setRevocationReason(reason: RevocationReason?): RevocationSignatureSubpackets
}