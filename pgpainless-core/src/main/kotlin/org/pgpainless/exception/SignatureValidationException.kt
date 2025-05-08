// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.SignatureType

class SignatureValidationException : PGPException {

    constructor(message: String?) : super(message)

    constructor(message: String?, underlying: Exception) : super(message, underlying)

    constructor(
        message: String,
        rejections: Map<PGPSignature, Exception>
    ) : super("$message: ${exceptionMapToString(rejections)}")

    companion object {
        @JvmStatic
        private fun exceptionMapToString(rejections: Map<PGPSignature, Exception>): String =
            buildString {
                append(rejections.size).append(" rejected signatures:\n")
                for (signature in rejections.keys) {
                    append(sigTypeToString(signature.signatureType))
                        .append(' ')
                        .append(signature.creationTime)
                        .append(": ")
                        .append(rejections[signature]!!.message)
                        .append('\n')
                }
            }

        @JvmStatic
        private fun sigTypeToString(type: Int): String =
            SignatureType.fromCode(type)?.toString()
                ?: "0x${java.lang.Long.toHexString(type.toLong())}"
    }
}
