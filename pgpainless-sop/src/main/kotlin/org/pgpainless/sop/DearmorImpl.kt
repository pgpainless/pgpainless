// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.BufferedOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.util.io.Streams
import sop.Ready
import sop.exception.SOPGPException
import sop.operation.Dearmor

/** Implementation of the `dearmor` operation using PGPainless. */
class DearmorImpl : Dearmor {

    override fun data(data: InputStream): Ready {
        val decoder =
            try {
                PGPUtil.getDecoderStream(data)
            } catch (e: IOException) {
                throw SOPGPException.BadData(e)
            }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                BufferedOutputStream(outputStream).use {
                    Streams.pipeAll(decoder, it)
                    it.flush()
                    decoder.close()
                }
            }
        }
    }
}
