// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider
import org.pgpainless.util.Passphrase

/**
 * Implementation of the [SecretKeyRingProtector] which holds a map of key ids and their passwords.
 * In case the needed passphrase is not contained in the map, the `missingPassphraseCallback` will
 * be consulted, and the passphrase is added to the map.
 *
 * If you need to unlock multiple [PGPKeyRing] instances, it is advised to use a separate
 * [CachingSecretKeyRingProtector] instance for each ring.
 */
class CachingSecretKeyRingProtector : SecretKeyRingProtector, SecretKeyPassphraseProvider {

    private val cache: MutableMap<Long?, Passphrase>
    private val protector: SecretKeyRingProtector
    private val provider: SecretKeyPassphraseProvider?

    constructor() : this(null)

    constructor(
        missingPassphraseCallback: SecretKeyPassphraseProvider?
    ) : this(
        mapOf<Long, Passphrase>(),
        KeyRingProtectionSettings.secureDefaultSettings(),
        missingPassphraseCallback)

    constructor(
        passphrases: Map<Long, Passphrase>,
        protectionSettings: KeyRingProtectionSettings,
        missingPassphraseCallback: SecretKeyPassphraseProvider?
    ) {
        this.cache = passphrases.toMutableMap()
        this.protector = PasswordBasedSecretKeyRingProtector(protectionSettings, this)
        this.provider = missingPassphraseCallback
    }

    /**
     * Add a passphrase to the cache. If the cache already contains a passphrase for the given
     * key-id, a [IllegalArgumentException] is thrown. The reason for this is to prevent accidental
     * override of passphrases when dealing with multiple key rings containing a key with the same
     * key-id but different passphrases.
     *
     * If you can ensure that there will be no key-id clash, and you want to replace the passphrase,
     * you can use [replacePassphrase] to replace the passphrase.
     *
     * @param keyId id of the key
     * @param passphrase passphrase
     */
    fun addPassphrase(keyId: Long, passphrase: Passphrase) = apply {
        require(!cache.containsKey(keyId)) {
            "The cache already holds a passphrase for ID ${keyId.openPgpKeyId()}.\n" +
                "If you want to replace this passphrase, use replacePassphrase(Long, Passphrase) instead."
        }
        cache[keyId] = passphrase
    }

    /**
     * Replace the passphrase for the given key-id in the cache.
     *
     * @param keyId keyId
     * @param passphrase passphrase
     */
    fun replacePassphrase(keyId: Long, passphrase: Passphrase) = apply { cache[keyId] = passphrase }

    /**
     * Remember the given passphrase for all keys in the given key ring. If for the key-id of any
     * key on the key ring the cache already contains a passphrase, a [IllegalArgumentException] is
     * thrown before any changes are committed to the cache. This is to prevent accidental
     * passphrase override when dealing with multiple key rings containing keys with conflicting
     * key-ids.
     *
     * If you can ensure that there will be no key-id clashes, and you want to replace the
     * passphrases for the key ring, use [replacePassphrase] instead.
     *
     * If you need to unlock multiple [PGPKeyRing], it is advised to use a separate
     * [CachingSecretKeyRingProtector] instance for each ring.
     *
     * @param keyRing key ring
     * @param passphrase passphrase
     */
    fun addPassphrase(keyRing: PGPKeyRing, passphrase: Passphrase) = apply {
        // check for existing passphrases before doing anything
        keyRing.publicKeys.forEach {
            require(!cache.containsKey(it.keyID)) {
                "The cache already holds a passphrase for the key with ID ${it.keyID.openPgpKeyId()}.\n" +
                    "If you want to replace the passphrase, use replacePassphrase(PGPKeyRing, Passphrase) instead."
            }
        }

        // only then instert
        keyRing.publicKeys.forEach { cache[it.keyID] = passphrase }
    }

    /**
     * Replace the cached passphrases for all keys in the key ring with the provided passphrase.
     *
     * @param keyRing key ring
     * @param passphrase passphrase
     */
    fun replacePassphrase(keyRing: PGPKeyRing, passphrase: Passphrase) = apply {
        keyRing.publicKeys.forEach { cache[it.keyID] = passphrase }
    }

    /**
     * Remember the given passphrase for the given (sub-)key.
     *
     * @param key key
     * @param passphrase passphrase
     */
    fun addPassphrase(key: PGPPublicKey, passphrase: Passphrase) =
        addPassphrase(key.keyID, passphrase)

    /**
     * Remember the given passphrase for the key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @param passphrase passphrase
     */
    fun addPassphrase(fingerprint: OpenPgpFingerprint, passphrase: Passphrase) =
        addPassphrase(fingerprint.keyId, passphrase)

    /**
     * Remove a passphrase from the cache. The passphrase will be cleared and then removed.
     *
     * @param keyId id of the key
     */
    fun forgetPassphrase(keyId: Long) = apply { cache.remove(keyId)?.clear() }

    /**
     * Forget the passphrase to all keys in the provided key ring.
     *
     * @param keyRing key ring
     */
    fun forgetPassphrase(keyRing: PGPKeyRing) = apply {
        keyRing.publicKeys.forEach { forgetPassphrase(it) }
    }

    /**
     * Forget the passphrase of the given public key.
     *
     * @param key key
     */
    fun forgetPassphrase(key: PGPPublicKey) = apply { forgetPassphrase(key.keyID) }

    override fun getPassphraseFor(keyId: Long?): Passphrase? {
        return if (hasPassphrase(keyId)) cache[keyId]
        else provider?.getPassphraseFor(keyId)?.also { cache[keyId] = it }
    }

    override fun hasPassphrase(keyId: Long?) = cache[keyId]?.isValid ?: false

    override fun hasPassphraseFor(keyId: Long) = hasPassphrase(keyId)

    override fun getDecryptor(keyId: Long) = protector.getDecryptor(keyId)

    override fun getEncryptor(keyId: Long) = protector.getEncryptor(keyId)
}
