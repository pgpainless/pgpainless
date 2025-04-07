// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.operator.PGPDigestCalculator

fun OpenPGPImplementation.checksumCalculator(): PGPDigestCalculator {
    return pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
}
