// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import java.util.*
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.key.protection.SecretKeyRingProtector

class KeyWithUnsupportedSignatureSubpacketTest {

    @Test
    fun `can set new expiration date on key containing unknown subpacket 34`() {
        val armoredKey =
            """-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEZWiyNhYJKwYBBAHaRw8BAQdA71QipJ0CAqOEqQWjuoQE4E7LarKSrNDwE/6K
bQNrCLwAAQCtJ8kVG2AmbDfdVtr/7Ag+yBh0oCvjRvyUCOyIbruOeg+6tClTdWJw
YWNrZXQzNCBUZXN0S2V5IDx0ZXN0QHBncGFpbmxlc3Mub3JnPoiTBBMWCgA7FiEE
zhy5yrnZYU/iBza4G03SQVuWqx0FAmVosjYCGwMFCwkIBwICIgIGFQoJCAsCBBYC
AwECHgcCF4AACgkQG03SQVuWqx1UGgD+IYLeh9t5eJCEnzueuOTYnTnrzyhnLgm9
dw5qwMXU8VQA/28GCOb7610hyjiBbrrcshkWAKuMwp8bUSz5FOeS5cQEnF0EZWiy
NhIKKwYBBAGXVQEFAQEHQK99ClLDYtn0I2b6Y26NhaL0RWcrNoI/ci0xgXEK2L0Y
AwEIBwAA/06qciQHI0v7MP2LMWm/ZuTJwzlPqV8VsBhrDMyUPUD4D52IeAQYFgoA
IBYhBM4cucq52WFP4gc2uBtN0kFblqsdBQJlaLI2AhsMAAoJEBtN0kFblqsdRQ0A
/iUJ/Fp+D2RjZL+aiwByIxPCVvMJ7a28+GQGjg3hsU2BAP474dfOOVZiTDLWWxsB
wxfzOAQxXDhgR9xd/Lk3MNJxDg==
=YAt0
-----END PGP PRIVATE KEY BLOCK-----"""
        val key: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(armoredKey)!!
        PGPainless.modifyKeyRing(secretKey = key)
            .setExpirationDate(Date(), SecretKeyRingProtector.unprotectedKeys())
            .done()
    }
}
