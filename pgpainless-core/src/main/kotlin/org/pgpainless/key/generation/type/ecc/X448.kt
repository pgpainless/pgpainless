package org.pgpainless.key.generation.type.ecc

import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

class X448 : KeyType {
    override val name: String = "X448"
    override val algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.X448
    override val bitStrength: Int = 448

    override fun generateKeyPair(generator: PGPKeyPairGenerator): PGPKeyPair {
        return generator.generateX448KeyPair()
    }
}
