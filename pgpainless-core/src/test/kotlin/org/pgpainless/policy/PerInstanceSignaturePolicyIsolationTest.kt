// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy

import java.util.Date
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.HashAlgorithm

class PerInstanceSignaturePolicyIsolationTest {

    /**
     * Regression test for finding #1 in
     * [GHSA-5fmp-48ff-rx9p](https://github.com/pgpainless/pgpainless/security/advisories/GHSA-5fmp-48ff-rx9p)
     *
     * @see
     *   [finding #1](https://github.com/pgpainless/pgpainless/security/advisories/GHSA-5fmp-48ff-rx9p)
     */
    @Test
    fun `Per-instance signature policy cannot be weakened by a later lenient api instance`() {
        val now = Date()
        val strictAPI = PGPainless()
        assertFalse(
            strictAPI.implementation
                .policy()
                .isAcceptableDocumentSignatureHashAlgorithm(HashAlgorithm.SHA1.algorithmId, now),
            "Strict API does not allow data signatures using SHA-1")

        // Instantiate lenient API, which by finding #1 in GHSA-5fmp-48ff-rx9p overwrote
        //  the shared OpenPGPImplementation instances policy member, causing the strict API to
        //  inherit the lenient instance's config
        val lenientAPI = PGPainless(Policy.wildcardPolicy())

        assertFalse(
            strictAPI.implementation
                .policy()
                .isAcceptableDocumentSignatureHashAlgorithm(HashAlgorithm.SHA1.algorithmId, now),
            "Later lenient API instance MUST NOT overwrite strict APIs policy")
    }
}
