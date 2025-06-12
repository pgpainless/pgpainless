package org.pgpainless.key.modification.secretkeyring

import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyEditor
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator
import org.pgpainless.PGPainless
import org.pgpainless.bouncycastle.extensions.getKeyVersion
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import java.util.*

class OpenPGPKeyUpdater(
    private var key: OpenPGPKey,
    private val protector: SecretKeyRingProtector,
    private val api: PGPainless = PGPainless.getInstance(),
    private val policy: Policy = api.algorithmPolicy,
    private val referenceTime: Date = Date()
) {

    private val keyEditor = OpenPGPKeyEditor(key, protector)

    fun extendExpirationIfExpiresBefore(expiresBeforeSeconds: Long,
                                        newExpirationTimeSecondsFromNow: Long? = _5YEARS
    ) = apply {
        require(expiresBeforeSeconds > 0) {
            "Time period to check expiration within MUST be positive."
        }
        require(newExpirationTimeSecondsFromNow == null || newExpirationTimeSecondsFromNow > 0) {
            "New expiration period MUST be null or positive."
        }
    }

    fun replaceRejectedAlgorithmPreferences(addNewAlgorithms: Boolean = false) = apply {

    }

    fun replaceWeakSubkeys(
        revokeWeakKeys: Boolean = true,
        signingKeysOnly: Boolean
    ) {
        replaceWeakSigningSubkeys(revokeWeakKeys)
        if (!signingKeysOnly) {
            replaceWeakEncryptionSubkeys(revokeWeakKeys)
        }
    }

    fun replaceWeakEncryptionSubkeys(
        revokeWeakKeys: Boolean,
        keyPairGeneratorCallback: KeyPairGeneratorCallback = KeyPairGeneratorCallback.encryptionKey()
    ) {
        val encryptionKeys = key.getEncryptionKeys(referenceTime)

        if (encryptionKeys.none {
                policy.publicKeyAlgorithmPolicy.isAcceptable(it.algorithm, it.pgpPublicKey.bitStrength)
            }
        ) {
            keyEditor.addEncryptionSubkey(keyPairGeneratorCallback)
        }

        if (revokeWeakKeys) {
            encryptionKeys.filterNot {
                it.keyIdentifier.matches(key.primaryKey.keyIdentifier)
            }.forEach {
                keyEditor.revokeComponentKey(it)
            }
        }
    }

    fun replaceWeakSigningSubkeys(
        revokeWeakKeys: Boolean,
        keyPairGenerator: PGPKeyPairGenerator = provideKeyPairGenerator(),
        keyPairGeneratorCallback: KeyPairGeneratorCallback = KeyPairGeneratorCallback.signingKey()
    ) {
        val weakSigningKeys = key.getSigningKeys(referenceTime)

        if (weakSigningKeys.none {
                policy.publicKeyAlgorithmPolicy.isAcceptable(it.algorithm, it.pgpPublicKey.bitStrength)
            }
        ) {
            keyEditor.addSigningSubkey(keyPairGeneratorCallback)
        }

        if (revokeWeakKeys) {
            weakSigningKeys.filterNot { it.keyIdentifier.matches(key.primaryKey.keyIdentifier) }
                .forEach {
                    keyEditor.revokeComponentKey(it)
                }
        }

        keyPairGeneratorCallback.generateFrom(keyPairGenerator)
    }

    private fun provideKeyPairGenerator(): PGPKeyPairGenerator {
        return api.implementation.pgpKeyPairGeneratorProvider()
            .get(key.primaryKey.getKeyVersion().numeric, referenceTime)
    }

    fun finish(): OpenPGPKey {

    }

    companion object {
        const val SECOND: Long = 1000
        const val MINUTE: Long = 60 * SECOND
        const val HOUR: Long = 60 * MINUTE
        const val DAY: Long = 24 * HOUR
        const val YEAR: Long = 365 * DAY
        const val _5YEARS: Long = 5 * YEAR
    }
}
