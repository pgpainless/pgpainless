// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import kotlin.jvm.Throws
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.OpenPgpInputStream
import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.Ready
import sop.exception.SOPGPException
import sop.operation.Armor

/** Implementation of the `armor` operation using PGPainless. */
class ArmorImpl(private val api: PGPainless) : Armor {

    @Throws(SOPGPException.BadData::class)
    override fun data(data: InputStream): Ready {
        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                // By buffering the output stream, we can improve performance drastically
                val bufferedOutputStream = BufferedOutputStream(outputStream)

                // Determine the nature of the given data
                val openPgpIn = OpenPgpInputStream(data)
                openPgpIn.reset()

                if (openPgpIn.isAsciiArmored) {
                    // armoring already-armored data is an idempotent operation
                    Streams.pipeAll(openPgpIn, bufferedOutputStream)
                    bufferedOutputStream.flush()
                    openPgpIn.close()
                    return
                }

                val armor = ArmoredOutputStreamFactory.get(bufferedOutputStream)
                Streams.pipeAll(openPgpIn, armor)
                bufferedOutputStream.flush()
                armor.close()
                openPgpIn.close()
            }
        }
    }
}
