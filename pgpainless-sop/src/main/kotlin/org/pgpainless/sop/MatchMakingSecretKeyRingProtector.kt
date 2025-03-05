// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.pgpainless.bouncycastle.extensions.isDecrypted
import org.pgpainless.bouncycastle.extensions.unlock
import org.pgpainless.key.protection.CachingSecretKeyRingProtector
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase

/**
 * Implementation of the [SecretKeyRingProtector] which can be handed passphrases and keys
 * separately, and which then matches up passphrases and keys when needed.
 */
class MatchMakingSecretKeyRingProtector : SecretKeyRingProtector {

    private val passphrases = mutableSetOf<Passphrase>()
    private val keys = mutableSetOf<PGPSecretKeyRing>()
    private val protector = CachingSecretKeyRingProtector()

    fun addPassphrase(passphrase: Passphrase) = apply {
        if (passphrase.isEmpty) {
            return@apply
        }

        if (!passphrases.add(passphrase)) {
            return@apply
        }

        keys.forEach { key ->
            for (subkey in key) {
                if (protector.hasPassphrase(subkey.keyID)) {
                    continue
                }

                if (testPassphrase(passphrase, subkey)) {
                    protector.addPassphrase(subkey.keyIdentifier, passphrase)
                }
            }
        }
    }

    fun addSecretKey(key: PGPSecretKeyRing) = apply {
        if (!keys.add(key)) {
            return@apply
        }

        key.forEach { subkey ->
            if (subkey.isDecrypted()) {
                protector.addPassphrase(subkey.keyIdentifier, Passphrase.emptyPassphrase())
            } else {
                passphrases.forEach { passphrase ->
                    if (testPassphrase(passphrase, subkey)) {
                        protector.addPassphrase(subkey.keyIdentifier, passphrase)
                    }
                }
            }
        }
    }

    private fun testPassphrase(passphrase: Passphrase, key: PGPSecretKey): Boolean =
        try {
            key.unlock(passphrase)
            true
        } catch (e: PGPException) {
            // Wrong passphrase
            false
        }

    override fun hasPassphraseFor(keyIdentifier: KeyIdentifier): Boolean =
        protector.hasPassphrase(keyIdentifier)

    override fun getDecryptor(keyIdentifier: KeyIdentifier): PBESecretKeyDecryptor? =
        protector.getDecryptor(keyIdentifier)

    override fun getEncryptor(keyIdentifier: KeyIdentifier): PBESecretKeyEncryptor? =
        protector.getEncryptor(keyIdentifier)

    override fun getKeyPassword(p0: OpenPGPKey.OpenPGPSecretKey): CharArray? =
        protector.getKeyPassword(p0)

    /** Clear all known passphrases from the protector. */
    fun clear() {
        passphrases.forEach { it.clear() }
        keys.forEach { protector.forgetPassphrase(it) }
    }
}
