// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.KeyPassphraseProvider
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider
import org.pgpainless.util.Passphrase
import kotlin.Throws

/**
 * Task of the [SecretKeyRingProtector] is to map encryptor/decryptor objects to key-ids.
 * [PBESecretKeyEncryptor]/[PBESecretKeyDecryptor] are used to encrypt/decrypt secret keys using a
 * passphrase.
 *
 * While it is easy to create an implementation of this interface that fits your needs, there are a
 * bunch of implementations ready for use.
 */
interface SecretKeyRingProtector : KeyPassphraseProvider {

    /**
     * Returns true, if the protector has a passphrase for the key with the given key-id.
     *
     * @param keyId key id
     * @return true if it has a passphrase, false otherwise
     */
    fun hasPassphraseFor(keyId: Long): Boolean = hasPassphraseFor(KeyIdentifier(keyId))

    fun hasPassphraseFor(keyIdentifier: KeyIdentifier): Boolean

    /**
     * Return a decryptor for the key of id `keyId`. This method returns null if the key is
     * unprotected.
     *
     * @param keyId id of the key
     * @return decryptor for the key
     */
    @Throws(PGPException::class) fun getDecryptor(keyId: Long): PBESecretKeyDecryptor? =
        getDecryptor(KeyIdentifier(keyId))

    @Throws(PGPException::class) fun getDecryptor(keyIdentifier: KeyIdentifier): PBESecretKeyDecryptor?

    /**
     * Return an encryptor for the key of id `keyId`. This method returns null if the key is
     * unprotected.
     *
     * @param keyId id of the key
     * @return encryptor for the key
     */
    @Throws(PGPException::class) fun getEncryptor(keyId: Long): PBESecretKeyEncryptor? =
        getEncryptor(KeyIdentifier(keyId))

    @Throws(PGPException::class) fun getEncryptor(keyIdentifier: KeyIdentifier): PBESecretKeyEncryptor?

    companion object {

        /**
         * Return a protector for secret keys. The protector maintains an in-memory cache of
         * passphrases and can be extended with new passphrases at runtime.
         *
         * See [CachingSecretKeyRingProtector] for how to memorize/forget additional passphrases
         * during runtime.
         *
         * @param missingPassphraseCallback callback that is used to provide missing passphrases.
         * @return caching secret key protector
         */
        @JvmStatic
        fun defaultSecretKeyRingProtector(
            missingPassphraseCallback: SecretKeyPassphraseProvider?
        ): CachingSecretKeyRingProtector =
            CachingSecretKeyRingProtector(
                mapOf(),
                KeyRingProtectionSettings.secureDefaultSettings(),
                missingPassphraseCallback)

        /**
         * Use the provided passphrase to lock/unlock all keys in the provided key ring.
         *
         * This protector will use the provided passphrase to lock/unlock all subkeys present in the
         * provided keys object. For other keys that are not present in the ring, it will return
         * null.
         *
         * @param passphrase passphrase
         * @param keys key ring
         * @return protector
         */
        @JvmStatic
        fun unlockEachKeyWith(
            passphrase: Passphrase,
            keys: PGPSecretKeyRing
        ): SecretKeyRingProtector =
            fromPassphraseMap(keys.map { it.keyID }.associateWith { passphrase })

        /**
         * Use the provided passphrase to unlock any key.
         *
         * @param passphrase passphrase
         * @return protector
         */
        @JvmStatic
        fun unlockAnyKeyWith(passphrase: Passphrase): SecretKeyRingProtector =
            BaseSecretKeyRingProtector(SolitaryPassphraseProvider(passphrase))

        /**
         * Use the provided passphrase to lock/unlock only the provided (sub-)key. This protector
         * will only return a non-null encryptor/decryptor based on the provided passphrase if
         * [getEncryptor]/[getDecryptor] is getting called with the key-id of the provided key.
         *
         * Otherwise, this protector will always return null.
         *
         * @param passphrase passphrase
         * @param key key to lock/unlock
         * @return protector
         */
        @JvmStatic
        fun unlockSingleKeyWith(passphrase: Passphrase, key: PGPSecretKey): SecretKeyRingProtector =
            PasswordBasedSecretKeyRingProtector.forKey(key, passphrase)

        /**
         * Use the provided passphrase to lock/unlock only the provided (sub-)key. This protector
         * will only return a non-null encryptor/decryptor based on the provided passphrase if
         * [getEncryptor]/[getDecryptor] is getting called with the key-id of the provided key.
         *
         * Otherwise, this protector will always return null.
         *
         * @param passphrase passphrase
         * @param keyId id of the key to lock/unlock
         * @return protector
         */
        @JvmStatic
        fun unlockSingleKeyWith(passphrase: Passphrase, keyId: Long): SecretKeyRingProtector =
            PasswordBasedSecretKeyRingProtector.forKeyId(keyId, passphrase)

        /**
         * Protector for unprotected keys. This protector returns null for all
         * [getEncryptor]/[getDecryptor] calls, no matter what the key-id is.
         *
         * As a consequence, this protector can only "unlock" keys which are not protected using a
         * passphrase, and it will leave keys unprotected, should it be used to "protect" a key
         * (e.g. in
         * [org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor.changePassphraseFromOldPassphrase]).
         *
         * @return protector
         */
        @JvmStatic fun unprotectedKeys() = UnprotectedKeysProtector()

        /**
         * Use the provided map of key-ids and passphrases to unlock keys.
         *
         * @param passphraseMap map of key ids and their respective passphrases
         * @return protector
         */
        @JvmStatic
        fun fromPassphraseMap(passphraseMap: Map<Long, Passphrase>): SecretKeyRingProtector =
            CachingSecretKeyRingProtector(
                passphraseMap, KeyRingProtectionSettings.secureDefaultSettings(), null)
    }
}
