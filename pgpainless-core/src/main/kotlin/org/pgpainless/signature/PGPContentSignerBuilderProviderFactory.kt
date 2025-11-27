package org.pgpainless.signature

import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider
import org.pgpainless.algorithm.HashAlgorithm

interface PGPContentSignerBuilderProviderFactory {

    fun create(hashAlgorithm: HashAlgorithm): PGPContentSignerBuilderProvider
}
