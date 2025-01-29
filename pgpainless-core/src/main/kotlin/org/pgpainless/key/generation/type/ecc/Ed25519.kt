package org.pgpainless.key.generation.type.ecc

import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType

class Ed25519 : KeyType {
    override val name: String = "Ed25519"
    override val algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ED25519
    override val bitStrength: Int = 256

    override fun generateKeyPair(generator: PGPKeyPairGenerator): PGPKeyPair {
        return generator.generateEd25519KeyPair()
    }
}
