// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import org.bouncycastle.bcpg.sig.PreferredAlgorithms
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm

/** Convert the [PreferredAlgorithms] packet into a [Set] of [HashAlgorithm] preferences. */
fun PreferredAlgorithms?.toHashAlgorithms(): Set<HashAlgorithm> {
    return this?.preferences?.asSequence()?.map { HashAlgorithm.requireFromId(it) }?.toSet()
        ?: setOf()
}

/** Convert the [PreferredAlgorithms] packet into a [Set] of [SymmetricKeyAlgorithm] preferences. */
fun PreferredAlgorithms?.toSymmetricKeyAlgorithms(): Set<SymmetricKeyAlgorithm> {
    return this?.preferences?.asSequence()?.map { SymmetricKeyAlgorithm.requireFromId(it) }?.toSet()
        ?: setOf()
}

/** Convert the [PreferredAlgorithms] packet into a [Set] of [CompressionAlgorithm] preferences. */
fun PreferredAlgorithms?.toCompressionAlgorithms(): Set<CompressionAlgorithm> {
    return this?.preferences?.asSequence()?.map { CompressionAlgorithm.requireFromId(it) }?.toSet()
        ?: setOf()
}
