// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless

class KeyWithUnknownSecretKeyEncryptionMethodTest {

    // Test vector from https://gitlab.com/dkg/openpgp-hardware-secrets/-/merge_requests/2
    val KEY =
        """-----BEGIN PGP PRIVATE KEY BLOCK-----

xTQEZgWtcxYJKwYBBAHaRw8BAQdAlLK6UPQsVHR2ETk1SwVIG3tBmpiEtikYYlCy
1TIiqzb8zR08aGFyZHdhcmUtc2VjcmV0QGV4YW1wbGUub3JnPsKNBBAWCAA1AhkB
BQJmBa1zAhsDCAsJCAcKDQwLBRUKCQgLAhYCFiEEXlP8Tur0WZR+f0I33/i9Uh4O
HEkACgkQ3/i9Uh4OHEnryAD8CzH2ajJvASp46ApfI4pLPY57rjBX++d/2FQPRyqG
HJUA/RLsNNgxiFYmK5cjtQe2/DgzWQ7R6PxPC6oa3XM7xPcCxzkEZgWtcxIKKwYB
BAGXVQEFAQEHQE1YXOKeaklwG01Yab4xopP9wbu1E+pCrP1xQpiFZW5KAwEIB/zC
eAQYFggAIAUCZgWtcwIbDBYhBF5T/E7q9FmUfn9CN9/4vVIeDhxJAAoJEN/4vVIe
DhxJVTgA/1WaFrKdP3AgL0Ffdooc5XXbjQsj0uHo6FZSHRI4pchMAQCyJnKQ3RvW
/0gm41JCqImyg2fxWG4hY0N5Q7Rc6PyzDQ==
=3w/O
-----END PGP PRIVATE KEY BLOCK-----"""

    @Test
    @Disabled("Disabled since BC 1.77 chokes on the test key")
    fun testExtractCertificate() {
        val key = PGPainless.readKeyRing().secretKeyRing(KEY)!!
        val cert = PGPainless.extractCertificate(key)

        assertNotNull(cert)
        // Each secret key got its public key component extracted
        assertEquals(
            key.secretKeys.asSequence().map { it.keyID }.toSet(),
            cert.publicKeys.asSequence().map { it.keyID }.toSet())
    }
}
