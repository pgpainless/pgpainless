// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless

class ThirdPartySigsTest {

    val KEY_WITH_3RDPARTY_CERTIFICATION =
        """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Comment: 2933 CBF1 9C19 5FEC C3D8  F6BB 7875 DF0D 34D8 0659
        Comment: Alice

        mCYEaUKQbBvoc5joeGZFjSjl2LoEuEfTn4dzNPkF68PUTROte/Yn2LQFQWxpY2XC
        cQQTGwoAHRahBCkzy/GcGV/sw9j2u3h13w002AZZBYJpQpBsAAoJEHh13w002AZZ
        XM1wwAo+gEchltvtokJUM2alG9z/iCOzBVs7WONrPo5rDJb+RRXXhVz+Mw1lYGWo
        USe86sZiTnjThA+Ech7JZdoHwnUEEBYKACcFgmlCnn0JEG2VRHjfrsFLFqEE2gJf
        vjCRGba1de0nbZVEeN+uwUsAAM3RAP0fEo5u5CdRg849xsNYAPv1oHT03el6LyGc
        Bk44oz7INgD/cFTufapwXJJB5IRX+lJA84w++6Xg0SS9h9TBmQBMiw24JgRpQpBs
        GyB6+bOfuk3Xaqlv2y9W08EiasmbznRLVaPhlLYTdNzCwsAnBBgbCgCTFqEEKTPL
        8ZwZX+zD2Pa7eHXfDTTYBlkFgmlCkGwCmwJyoAQZGwoAHRahBB7oLGA9/n/GLv02
        vM2YyJHfn7e+BYJpQpBsAAoJEM2YyJHfn7e+b0/C2Cv/ujgLxz3TOGi5rTFW7LQ+
        8vxC25T7ryBmnXaBdZvv0dBvOXy7MpSzRIrgxJQQWpoDNLHFZKosEGYCCUwKAAoJ
        EHh13w002AZZLI0VnHaOFQRwf+6BCOD/+0d9JhYAOh6nP24pAc0kTeZ7UHZusysk
        SfhI5KGG2gFUEJlItnagBCsIzxV0GwFoLSwAuCYEaUKQbBnAZbXB6dCd6LT+HeS6
        1Js5qhp7S+GPhFW4MfGeCBU/F8J0BBgbCgAgFqEEKTPL8ZwZX+zD2Pa7eHXfDTTY
        BlkFgmlCkGwCmwwACgkQeHXfDTTYBllHw49G2YdupzV1pu1qk4KXgDtsVQumEthi
        fOXKC8sGfUZASw5bPNFMcWfT/nFrzmuvi01DD+pfUo9a8GoRAZ6qSQ0=
        =oG2x
        -----END PGP PUBLIC KEY BLOCK-----
    """
            .trimIndent()

    @Test
    fun test() {
        val api = PGPainless.getInstance()
        val key = api.readKey().parseCertificate(KEY_WITH_3RDPARTY_CERTIFICATION)
        api.inspect(key).primaryKeyExpirationDate
    }
}
