// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.TestKeys
import org.pgpainless.util.Passphrase

class PGPSecretKeyExtensionsTest {

    @Test
    fun `can successfully unlock protected secret key`() {
        val key = TestKeys.getCryptieSecretKeyRing()
        val secKey = key.secretKey

        val privKey = assertDoesNotThrow { secKey.unlock(TestKeys.CRYPTIE_PASSPHRASE) }
        assertNotNull(privKey)
    }

    @Test
    fun `cannot unlock protected secret key using empty passphrase`() {
        val key = TestKeys.getCryptieSecretKeyRing()
        val secKey = key.secretKey

        assertThrows<WrongPassphraseException> { secKey.unlock(Passphrase.emptyPassphrase()) }
    }

    @Test
    fun `can successfully unlock unprotected secret key with unprotectedKeys protector`() {
        val key = TestKeys.getEmilSecretKeyRing()
        val secKey = key.secretKey

        val privKey = assertDoesNotThrow { secKey.unlock() }
        assertNotNull(privKey)
    }

    @Test
    fun `can successfully unlock unprotected secret key with empty passphrase`() {
        val key = TestKeys.getEmilSecretKeyRing()
        val secKey = key.secretKey

        val privKey = assertDoesNotThrow { secKey.unlock(Passphrase.emptyPassphrase()) }
        assertNotNull(privKey)
    }

    @Test
    fun `openPgpFingerprint returns fitting fingerprint`() {
        val key = TestKeys.getEmilSecretKeyRing()

        assertEquals(TestKeys.EMIL_FINGERPRINT, key.openPgpFingerprint)
        assertEquals(TestKeys.EMIL_FINGERPRINT, key.secretKey.openPgpFingerprint)
    }

    @Test
    fun `publicKeyAlgorithm returns fitting algorithm`() {
        val key = TestKeys.getEmilSecretKeyRing()
        assertEquals(PublicKeyAlgorithm.ECDSA, key.secretKey.publicKeyAlgorithm)
    }
}
