// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.pgpainless.util.Passphrase

class CharSequenceExtensionsTest {

    @Test
    fun `toArray returns empty array for null`() {
        assertArrayEquals(emptyArray(), (null as CharSequence?).toArray())
    }

    @Test
    fun `toArray returns singleton array for non-null`() {
        assertArrayEquals(arrayOf("foo"), "foo".toArray())
    }

    @Test
    fun `toPassphrase returns emptyPassphrase for null`() {
        assertEquals(Passphrase.emptyPassphrase(), (null as CharSequence?).toPassphrase())
    }

    @Test
    fun `toPassphrase returns emptyPassphrase for empty string`() {
        assertEquals(Passphrase.emptyPassphrase(), "".toPassphrase())
    }

    @Test
    fun `toPassphrase returns emptyPassphrase for blank strings`() {
        listOf(" ", "  ", "\t", "\t ", " \t", "\n", " \n", "\n ", "\r\n").forEach {
            val passphrase = it.toPassphrase()
            assertTrue(it.isBlank())
            assertEquals(Passphrase.emptyPassphrase(), passphrase)
        }
    }

    @Test
    fun `toPassphrase returns non-empty passphrase for non-blank string`() {
        listOf("sw0rdf1sh", "1", "foo", "bar", "dragon", "123456").forEach {
            val passphrase = it.toPassphrase()
            assertEquals(Passphrase.fromPassword(it), passphrase)
            assertFalse(it.isBlank())
        }
    }
}
