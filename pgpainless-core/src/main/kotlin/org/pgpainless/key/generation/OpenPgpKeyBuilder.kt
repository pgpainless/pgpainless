package org.pgpainless.key.generation

import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.provider.ProviderFactory
import java.security.KeyPairGenerator
import java.util.Date

class OpenPgpKeyBuilder {

    fun buildV4Key(
        type: KeyType,
        creationTime: Date = Date()
    ): V4PrimaryKeyBuilder = V4PrimaryKeyBuilder(type, creationTime)

    abstract class V4KeyBuilder<T: V4KeyBuilder<T>>(
        protected val type: KeyType,
        protected val creationTime: Date,
        val certificateCreationTime: Date = Date()
    ) {

        internal val keyPair = generateKeyPair()

        fun subkey(
            type: KeyType,
            creationTime: Date = certificateCreationTime
        ): V4SubkeyBuilder = V4SubkeyBuilder(type, creationTime, this)

        fun generate(): PGPSecretKeyRing {
            val keys = collectKeysForGeneration()

            assert(keys.first() is V4PrimaryKeyBuilder)
            assert(keys.drop(1).all { it is V4SubkeyBuilder })

            val primaryKey: V4PrimaryKeyBuilder = keys.first() as V4PrimaryKeyBuilder

        }

        private fun collectKeysForGeneration(): List<V4KeyBuilder<*>> =
            if (this is V4SubkeyBuilder) {
                predecessor.collectKeysForGeneration().plus(this)
            } else {
                listOf(this)
            }

        private fun generateKeyPair(): PGPKeyPair {
            // Create raw Key Pair
            val keyPair = KeyPairGenerator.getInstance(type.name, ProviderFactory.provider)
                .also { it.initialize(type.algorithmSpec) }
                .generateKeyPair()

            // Form PGP Key Pair
            return ImplementationFactory.getInstance()
                .getPGPV4KeyPair(type.algorithm, keyPair, creationTime)
        }
    }

    class V4PrimaryKeyBuilder(
        type: KeyType,
        creationTime: Date
    ): V4KeyBuilder<V4PrimaryKeyBuilder>(type, creationTime) {

        fun userId(userId: CharSequence) = userId(userId, OpenPgpV4KeyGenerator.Preferences())

        fun userId(userId: CharSequence, preferences: OpenPgpV4KeyGenerator.Preferences) = apply {
            keyPair.publicKey.
        }

        fun selfSignature(preferences: OpenPgpV4KeyGenerator.Preferences) = apply {

        }
    }

    class V4SubkeyBuilder(
        type: KeyType,
        creationTime: Date,
        internal val predecessor: V4KeyBuilder<*>,
    ): V4KeyBuilder<V4SubkeyBuilder>(type, creationTime, predecessor.certificateCreationTime) {
        fun bindingSignature(preferences: OpenPgpV4KeyGenerator.Preferences) = apply {

        }
    }
}

fun test() {
    OpenPgpKeyBuilder()
        .buildV4Key(KeyType.RSA(RsaLength._4096))
        .selfSignature(OpenPgpV4KeyGenerator.Preferences())
        .userId("Alice", OpenPgpV4KeyGenerator.Preferences())
        .subkey(KeyType.EDDSA(EdDSACurve._Ed25519))
        .bindingSignature(OpenPgpV4KeyGenerator.Preferences())
        .subkey(KeyType.XDH(XDHSpec._X25519))
        .bindingSignature(OpenPgpV4KeyGenerator.Preferences())
}
