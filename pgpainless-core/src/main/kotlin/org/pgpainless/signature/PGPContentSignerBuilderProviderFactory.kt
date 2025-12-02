// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature

import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider
import org.pgpainless.algorithm.HashAlgorithm

interface PGPContentSignerBuilderProviderFactory {

    fun create(hashAlgorithm: HashAlgorithm): PGPContentSignerBuilderProvider
}
