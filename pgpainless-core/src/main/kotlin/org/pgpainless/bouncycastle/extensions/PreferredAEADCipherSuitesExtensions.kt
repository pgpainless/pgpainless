// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites
import org.pgpainless.algorithm.AEADCipherMode

/** Convert the [PreferredAEADCiphersuites] packet into a [Set] of [AEADCipherMode]. */
fun PreferredAEADCiphersuites?.toAEADCipherModes(): Set<AEADCipherMode> {
    return this?.algorithms?.asSequence()?.map { AEADCipherMode(it) }?.toSet() ?: setOf()
}
