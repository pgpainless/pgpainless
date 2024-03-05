// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.PGPainless
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.key.TestKeys
import org.pgpainless.key.protection.SecretKeyRingProtector
import java.io.ByteArrayOutputStream

class PGPSecretKeyRingExtensionsTest {

    @Test
    fun testHasPgpSecretKeyRing() {
        val key = TestKeys.getEmilSecretKeyRing()
        assertTrue(key.hasSecretKey(TestKeys.EMIL_KEY_ID))
        assertTrue(key.hasSecretKey(TestKeys.EMIL_FINGERPRINT))

        assertFalse(key.hasSecretKey(TestKeys.ROMEO_KEY_ID))
        assertFalse(key.hasSecretKey(TestKeys.ROMEO_FINGERPRINT))
    }

    @Test
    fun testRequireSecretKey() {
        val key = TestKeys.getEmilSecretKeyRing()
        assertNotNull(key.requireSecretKey(TestKeys.EMIL_KEY_ID))
        assertNotNull(key.requireSecretKey(TestKeys.EMIL_FINGERPRINT))

        assertThrows<NoSuchElementException> {
            key.requireSecretKey(TestKeys.ROMEO_KEY_ID)
        }
        assertThrows<NoSuchElementException> {
            key.requireSecretKey(TestKeys.ROMEO_FINGERPRINT)
        }
    }

    @Test
    fun testGetSecretKeyForSignature() {
        val key = TestKeys.getEmilSecretKeyRing()
        val signer = PGPainless.encryptAndOrSign()
            .onOutputStream(ByteArrayOutputStream())
            .withOptions(
                ProducerOptions.sign(SigningOptions.get()
                    .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), key)
                )
            )
        signer.write("Hello, World!\n".toByteArray())
        signer.close()
        val sig = signer.result.detachedSignatures.first().value.first()

        assertNotNull(key.getSecretKeyFor(sig))
        assertNull(TestKeys.getRomeoSecretKeyRing().getSecretKeyFor(sig))
    }
}
