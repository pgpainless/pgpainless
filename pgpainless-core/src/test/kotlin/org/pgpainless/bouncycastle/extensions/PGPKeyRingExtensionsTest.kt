// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.key.TestKeys

class PGPKeyRingExtensionsTest {

    @Test
    fun `public key ring has public key`() {
        val key = TestKeys.getJulietPublicKeyRing()
        assertTrue(key.hasPublicKey(TestKeys.JULIET_KEY_ID))
        assertTrue(key.hasPublicKey(TestKeys.JULIET_FINGERPRINT))

        assertFalse(key.hasPublicKey(TestKeys.ROMEO_KEY_ID))
        assertFalse(key.hasPublicKey(TestKeys.ROMEO_FINGERPRINT))
    }

    @Test
    fun `secret key ring has public key`() {
        val key = TestKeys.getJulietSecretKeyRing()
        assertTrue(key.hasPublicKey(TestKeys.JULIET_KEY_ID))
        assertTrue(key.hasPublicKey(TestKeys.JULIET_FINGERPRINT))

        assertFalse(key.hasPublicKey(TestKeys.ROMEO_KEY_ID))
        assertFalse(key.hasPublicKey(TestKeys.ROMEO_FINGERPRINT))
    }

    @Test
    fun `test requirePublicKey on secret key ring`() {
        val key = TestKeys.getJulietSecretKeyRing()
        assertNotNull(assertDoesNotThrow { key.requirePublicKey(TestKeys.JULIET_KEY_ID) })
        assertNotNull(assertDoesNotThrow { key.requirePublicKey(TestKeys.JULIET_FINGERPRINT) })

        assertThrows<NoSuchElementException> { key.requirePublicKey(TestKeys.ROMEO_KEY_ID) }
        assertThrows<NoSuchElementException> { key.requirePublicKey(TestKeys.ROMEO_FINGERPRINT) }
    }

    @Test
    fun `test requirePublicKey on public key ring`() {
        val key = TestKeys.getJulietPublicKeyRing()
        assertNotNull(assertDoesNotThrow { key.requirePublicKey(TestKeys.JULIET_KEY_ID) })
        assertNotNull(assertDoesNotThrow { key.requirePublicKey(TestKeys.JULIET_FINGERPRINT) })

        assertThrows<NoSuchElementException> { key.requirePublicKey(TestKeys.ROMEO_KEY_ID) }
        assertThrows<NoSuchElementException> { key.requirePublicKey(TestKeys.ROMEO_FINGERPRINT) }
    }
}
