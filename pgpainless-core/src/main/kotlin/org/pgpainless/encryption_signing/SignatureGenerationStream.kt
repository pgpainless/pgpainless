// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.OutputStream

/** OutputStream which has the task of updating signature generators for written data. */
class SignatureGenerationStream(
    private val wrapped: OutputStream,
    private val options: SigningOptions?
) : OutputStream() {

    override fun close() = wrapped.close()

    override fun flush() = wrapped.flush()

    override fun write(b: Int) {
        wrapped.write(b)
        options?.run {
            signingMethods.values.forEach { it.signatureGenerator.update((b and 0xff).toByte()) }
        }
    }

    override fun write(b: ByteArray) = write(b, 0, b.size)

    override fun write(b: ByteArray, off: Int, len: Int) {
        wrapped.write(b, off, len)
        options?.run { signingMethods.values.forEach { it.signatureGenerator.update(b, off, len) } }
    }
}
