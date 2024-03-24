// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.OutputStream

/** [OutputStream] that simply discards bytes written to it. */
class NullOutputStream : OutputStream() {

    override fun write(p0: Int) {
        // nop
    }

    override fun write(b: ByteArray) {
        // nop
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        // nop
    }

    override fun close() {
        // nop
    }

    override fun flush() {
        // nop
    }
}
