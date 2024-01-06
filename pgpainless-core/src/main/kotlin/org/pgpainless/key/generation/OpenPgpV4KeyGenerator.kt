package org.pgpainless.key.generation

import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.policy.Policy
import java.util.*

class OpenPgpV4KeyGenerator(
    private val policy: Policy,
    private val referenceTime: Date = Date()
) {

    fun primaryKey(
        type: KeyType,
        vararg flag: KeyFlag = arrayOf(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
    ) = primaryKey(type, referenceTime, *flag)

    fun primaryKey(
        type: KeyType,
        creationTime: Date,
        vararg flag: KeyFlag = arrayOf(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
    ) = WithSubkeys(
        KeyDescription(type, creationTime, flag.toList()),
        policy,
        referenceTime
    )

    class WithSubkeys(
        private val primaryKey: KeyDescription,
        private val policy: Policy,
        private val referenceTime: Date
    ) {

        val builder = OpenPgpKeyBuilder()
            .buildV4Key(primaryKey.type)
            .

        init {

        }

        fun encryptionSubkey(
            type: KeyType,
            vararg flag: KeyFlag = arrayOf(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
        ) = encryptionSubkey(type, referenceTime, *flag)

        fun encryptionSubkey(
            type: KeyType,
            creationTime: Date,
            vararg flag: KeyFlag = arrayOf(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
        ) = subkey(type, creationTime, *flag)

        fun signingSubkey(
            type: KeyType
        ) = signingSubkey(type, referenceTime)

        fun signingSubkey(
            type: KeyType,
            creationTime: Date
        ) = subkey(type, creationTime, KeyFlag.SIGN_DATA)

        fun subkey(
            type: KeyType,
            vararg flag: KeyFlag
        ) = subkey(type, referenceTime, *flag)

        fun subkey(
            type: KeyType,
            creationTime: Date = referenceTime,
            vararg flag: KeyFlag
        ) = apply {

        }

        fun noUserId(
            preferences: Preferences
        ): PGPSecretKeyRing {

        }

        fun userId(
            userId: CharSequence,
            preferences: Preferences
        ): WithUserIds = WithUserIds().apply {
            userId(userId, preferences)
        }
    }

    class WithUserIds {
        fun userId(
            userId: CharSequence,
            preferences: Preferences
        ): WithUserIds {

        }

        fun done(): PGPSecretKeyRing {

        }

        fun directKeySignature(
            preferences: Preferences
        ): PGPSecretKeyRing {

        }
    }

    data class KeyDescription(
        val type: KeyType,
        val creationTime: Date,
        val flags: List<KeyFlag>
    )

    data class Preferences()

}
