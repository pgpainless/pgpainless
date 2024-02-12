package org.pgpainless.key.generation

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.*
import org.bouncycastle.bcpg.PublicSubkeyPacket
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
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
            return generatePgpKeyPair(type, creationTime)
        }

        override fun generateSubkey(type: KeyType, creationTime: Date): PGPKeyPair {
            val keyPair = generatePgpKeyPair(type, creationTime)

            // We need to convert the keyPair which is in primary key format into subkey format
            val fpCalc = ImplementationFactory.getInstance().keyFingerprintCalculator
            val pubkey = keyPair.publicKey
            val privkey = keyPair.privateKey
            // transform to subkey packet
            val subkey =
                PublicSubkeyPacket(
                    pubkey.algorithm, pubkey.creationTime, pubkey.publicKeyPacket.key)
            // return as PGP key pair
            return PGPKeyPair(
                PGPPublicKey(subkey, fpCalc),
                PGPPrivateKey(pubkey.keyID, subkey, privkey.privateKeyDataPacket))
        }
    }
}
