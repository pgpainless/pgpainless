// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.InputStream
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.signature.SignatureUtils

class SignatureReader {
    fun fromArmor(armor: String): List<PGPSignature> = SignatureUtils.readSignatures(armor)

    fun fromBytes(bytes: ByteArray): List<PGPSignature> = SignatureUtils.readSignatures(bytes)

    fun fromStream(inputStream: InputStream): List<PGPSignature> =
        SignatureUtils.readSignatures(inputStream)
}
