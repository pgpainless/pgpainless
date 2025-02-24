// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites.Combination

data class AEADCipherMode(val aeadAlgorithm: AEADAlgorithm, val ciphermode: SymmetricKeyAlgorithm) {
    constructor(
        combination: Combination
    ) : this(
        AEADAlgorithm.requireFromId(combination.aeadAlgorithm),
        SymmetricKeyAlgorithm.requireFromId(combination.symmetricAlgorithm))
}
