package org.pgpainless.key.generation

import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import java.util.Date

fun buildV4(
    policy: Policy = PGPainless.getPolicy(),
    creationTime: Date = Date()
): OpinionatedPrimaryKeyBuilder.V4 {
    return OpinionatedPrimaryKeyBuilder.V4(policy, creationTime)
}

fun buildV6(
    policy: Policy = PGPainless.getPolicy(),
    creationTime: Date = Date()
): OpinionatedPrimaryKeyBuilder.V6 {
    return OpinionatedPrimaryKeyBuilder.V6(policy, creationTime)
}

fun test() {
    // Unopinionated
    buildV4()
        .unopinionated()
        .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519), Date()) {
            addDirectKeySignature(SelfSignatureSubpackets.nop())
            addUserId("Alice <alice@pgpainless.org>")
        }
        .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519), Date()) {
            addBindingSignature(SelfSignatureSubpackets.nop())
        }
        .addSubkey(KeyType.XDH(XDHSpec._X25519), Date()) {
            addBindingSignature(SelfSignatureSubpackets.nop())
        }
        .build()

    // Opinionated
    buildV4()
        .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519), Date()) {
            addDirectKeySignature(SelfSignatureSubpackets.nop())
            addUserId("Alice")
        }
        .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519), Date()) {
            //
        }
        .build()

    // Unopinionated
    buildV6()
        .unopinionated()
        .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519), Date())
        .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519), Date())
        .build()

    // Opinionated
    buildV6()
        .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519), Date())
        .addSubkey(KeyType.XDH(XDHSpec._X25519), Date())
        .build()
}

abstract class PrimaryKeyBuilder<B : KeyBuilder<B>>(
    protected val creationTime: Date
) {
    abstract fun setPrimaryKey(
        type: KeyType,
        creationTime: Date = this.creationTime,
        function: ApplyToPrimaryKey.() -> Unit = {}): B
}

abstract class OpinionatedPrimaryKeyBuilder<B : Opinionated, U : Unopinionated>(
    protected val policy: Policy,
    creationTime: Date,
    protected val unopinionated: UnopinionatedPrimaryKeyBuilder<U>
) : PrimaryKeyBuilder<Opinionated>(creationTime) {

    fun unopinionated() = unopinionated

    class V4(
        policy: Policy,
        creationTime: Date
    ) : OpinionatedPrimaryKeyBuilder<Opinionated.V4, Unopinionated.V4>(
        policy,
        creationTime,
        UnopinionatedPrimaryKeyBuilder.V4(creationTime)
    ) {

        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToPrimaryKey.() -> Unit
        ): Opinionated.V4 {
            return Opinionated.V4(
                policy,
                unopinionated.setPrimaryKey(type, creationTime, function) as Unopinionated.V4)
        }
    }

    class V6(
        policy: Policy,
        creationTime: Date
    ) : OpinionatedPrimaryKeyBuilder<Opinionated.V6, Unopinionated.V6>(
        policy,
        creationTime,
        UnopinionatedPrimaryKeyBuilder.V6(creationTime)
    ) {
        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToPrimaryKey.() -> Unit
        ): Opinionated.V6 {
            return Opinionated.V6(
                policy,
                unopinionated.setPrimaryKey(type, creationTime, function) as Unopinionated.V6)
        }
    }
}

abstract class UnopinionatedPrimaryKeyBuilder<B : Unopinionated>(
    creationTime: Date
) : PrimaryKeyBuilder<Unopinionated>(
    creationTime
) {

    class V4(creationTime: Date) : UnopinionatedPrimaryKeyBuilder<Unopinionated.V4>(creationTime) {
        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToPrimaryKey.() -> Unit
        ): Unopinionated.V4 {
            return Unopinionated.V4()
        }
    }

    class V6(creationTime: Date) : UnopinionatedPrimaryKeyBuilder<Unopinionated.V6>(creationTime) {
        override fun setPrimaryKey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToPrimaryKey.() -> Unit
        ): Unopinionated.V6 {
            return Unopinionated.V6()
        }
    }
}

interface KeyBuilder<B : KeyBuilder<B>> {

    fun addSubkey(type: KeyType, creationTime: Date, function: ApplyToSubkey.() -> Unit = {}): B

    fun addEncryptionSubkey(type: KeyType, creationTime: Date, function: ApplyToSubkey.() -> Unit = {}): B {
        return addSubkey(type, creationTime, function)
    }

    fun build(): PGPSecretKeyRing
}

@JvmDefaultWithoutCompatibility
abstract class Opinionated(
    protected val policy: Policy
) : KeyBuilder<Opinionated> {

    abstract val unopinionated: Unopinionated

    override fun build(): PGPSecretKeyRing = unopinionated.build()

    class V4(
        policy: Policy,
        override val unopinionated: Unopinionated.V4 = Unopinionated.V4()
    ) : Opinionated(policy) {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToSubkey.() -> Unit
        ): V4 = apply {
            unopinionated.addSubkey(type, creationTime, function)
        }

    }

    class V6(
        policy: Policy,
        override val unopinionated: Unopinionated.V6 = Unopinionated.V6()
    ) : Opinionated(policy) {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToSubkey.() -> Unit
        ): V6 = apply {
            unopinionated.addSubkey(type, creationTime, function)
        }
    }
}

@JvmDefaultWithoutCompatibility
abstract class Unopinionated : KeyBuilder<Unopinionated> {

    class V4 : Unopinionated() {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToSubkey.() -> Unit
        ): V4 = apply {
            // Add key
        }

        override fun build(): PGPSecretKeyRing {
            TODO("Not yet implemented")
        }
    }

    class V6 : Unopinionated() {

        override fun addSubkey(
            type: KeyType,
            creationTime: Date,
            function: ApplyToSubkey.() -> Unit
        ): V6 = apply {
            // Add Key
        }

        override fun build(): PGPSecretKeyRing {
            TODO("Not yet implemented")
        }
    }
}

interface ApplyToPrimaryKey {
    fun addUserId(userId: CharSequence)

    fun addDirectKeySignature(subpacketsCallback: SelfSignatureSubpackets.Callback)
}

interface ApplyToSubkey {
    fun addBindingSignature(subpacketsCallback: SelfSignatureSubpackets.Callback)
}
