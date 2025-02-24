package org.pgpainless.decryption_verification

import org.bouncycastle.util.io.Streams
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CRLFInputStreamTest {

    @Test
    fun readRNOneByOne() {
        val bIn = "a\r\nb".byteInputStream()
        val crlfIn = OpenPgpMessageInputStream.CRLFInputStream(bIn)

        assertEquals('a'.code, crlfIn.read())
        assertEquals('\n'.code, crlfIn.read())
        assertEquals('b'.code, crlfIn.read())
        assertEquals(-1, crlfIn.read())
    }

    @Test
    fun readRNAtOnce() {
        val bIn = "a\r\nb".byteInputStream()
        val crlfIn = OpenPgpMessageInputStream.CRLFInputStream(bIn)

        val bytes = Streams.readAll(crlfIn)
        assertArrayEquals("a\nb".toByteArray(), bytes)
    }
}
