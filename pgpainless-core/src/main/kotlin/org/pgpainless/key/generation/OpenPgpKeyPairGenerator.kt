package org.pgpainless.key.generation

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.*
import org.bouncycastle.openpgp.PGPKeyPair
import org.pgpainless.bouncycastle.extensions.toPrimaryKeyFormat
import org.pgpainless.bouncycastle.extensions.toSubkeyFormat
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.provider.ProviderFactory

/** Generator interface for [PGPKeyPair] objects. */
internal interface OpenPgpKeyPairGenerator {

    /**
     * Generate a [PGPKeyPair] in primary key format.
     *
     * @param type key type
     * @param creationTime creation time of the key
     * @return primary key pair
     */
    fun generatePrimaryKey(type: KeyType, creationTime: Date): PGPKeyPair

    /**
     * Generate a [PGPKeyPair] in subkey format.
     *
     * @param type key type
     * @param creationTime creation time of the key
     * @return subkey pair
     */
    fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair

    /** Implementation of [OpenPgpKeyPairGenerator] which generates OpenPGP v4 keys. */
    class V4 : OpenPgpKeyPairGenerator {

        /**
         * Generate an asymmetric cipher key pair.
         *
         * @param type algorithm specification
         * @return key pair
         */
        private fun generateKeyPair(type: KeyType): KeyPair {
            return KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
                .also { it.initialize(type.algorithmSpec) }
                .generateKeyPair()
        }

        /**
         * Generate a PGP key pair.
         *
         * @param type key type
         * @param creationTime creation time of the key
         * @return pgp key pair
         */
        private fun generatePgpKeyPair(type: KeyType, creationTime: Date): PGPKeyPair {
            return ImplementationFactory.getInstance()
                .getPGPV4KeyPair(type.algorithm, generateKeyPair(type), creationTime)
        }

        override fun generatePrimaryKey(type: KeyType, creationTime: Date): PGPKeyPair {
            // already in primary key format
            return generatePgpKeyPair(type, creationTime).toPrimaryKeyFormat()
        }

        override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
            return generatePgpKeyPair(type, creationTime).toSubkeyFormat()
        }
    }
}
