// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.Signer
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import java.io.OutputStream
import java.security.MessageDigest

abstract class PGPHashContextContentSignerBuilder : PGPContentSignerBuilder {

    // Copied from BC, required since BCs class is package visible only
    internal class SignerOutputStream(
            private val signer: Signer
    ) : OutputStream() {
        override fun write(p0: Int) = signer.update(p0.toByte())
        override fun write(b: ByteArray) = signer.update(b, 0, b.size)
        override fun write(b: ByteArray, off: Int, len: Int) = signer.update(b, off, len)
    }

    internal class ExistingMessageDigest(
            private val digest: MessageDigest
    ) : Digest {

        override fun getAlgorithmName(): String = digest.algorithm
        override fun getDigestSize(): Int = digest.digestLength
        override fun update(b: Byte) = digest.update(b)
        override fun update(buf: ByteArray, inOff: Int, len: Int) = digest.update(buf)
        override fun doFinal(out: ByteArray, outOff: Int): Int {
            digest.digest().copyInto(out, outOff)
            return digestSize
        }
        override fun reset() {
            // Nope!
            // We cannot reset, since BCs signer classes are resetting in their init() methods, which would also reset
            // the messageDigest, losing its state. This would shatter our intention.
        }
    }
}