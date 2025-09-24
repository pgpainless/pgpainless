// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.TestKeys
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.ecc.EllipticCurve
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve

class PGPPublicKeyExtensionsTest {

    @Test
    fun `test getCurveName for all ECDSA curves`() {
        for (curve in EllipticCurve.values()) {
            val key =
                PGPainless.buildKeyRing()
                    .setPrimaryKey(KeySpec.getBuilder(KeyType.ECDSA(curve)))
                    .build()
                    .pgpSecretKeyRing
                    .publicKey

            assertEquals(curve.curveName, key.getCurveName())
        }
    }

    @Test
    fun `test getCurveName for legacy EdDSA curves`() {
        for (curve in EdDSALegacyCurve.values()) {
            val key =
                PGPainless.buildKeyRing()
                    .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(curve)))
                    .build()
                    .pgpSecretKeyRing
                    .publicKey

            assertEquals(curve.curveName, key.getCurveName())
        }
    }

    @Test
    fun `test getCurveName fails for non-curve keys`() {
        // RSA
        val key = TestKeys.getJulietPublicKeyRing()
        assertEquals(PublicKeyAlgorithm.RSA_GENERAL, key.publicKey.publicKeyAlgorithm)

        assertThrows<IllegalArgumentException> { key.publicKey.getCurveName() }
    }

    @Test
    fun `openPgpFingerprint returns fitting fingerprint`() {
        val key = TestKeys.getEmilSecretKeyRing()
        assertEquals(TestKeys.EMIL_FINGERPRINT, key.publicKey.openPgpFingerprint)
    }
}
