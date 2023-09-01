// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.fixes

import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey.Companion.unlockSecretKey

/**
 * Repair class to fix keys which use S2K usage of value [SecretKeyPacket.USAGE_CHECKSUM].
 * The method [replaceUsageChecksumWithUsageSha1] ensures that such keys are encrypted using
 * S2K usage [SecretKeyPacket.USAGE_SHA1] instead.
 *
 * @see <a href="https://github.com/pgpainless/pgpainless/issues/176">Related PGPainless Bug Report</a>
 * @see <a href="https://github.com/pgpainless/pgpainless/issues/178">Related PGPainless Feature Request</a>
 * @see <a href="https://github.com/bcgit/bc-java/issues/1020">Related upstream BC bug report</a>
 */
class S2KUsageFix {

    companion object {

        /**
         * Repair method for keys which use S2K usage <pre>USAGE_CHECKSUM</pre> which is deemed insecure.
         * This method fixes the private keys by changing them to <pre>USAGE_SHA1</pre> instead.
         *
         * @param keys keys
         * @param protector protector to unlock and re-lock affected private keys
         * @param skipKeysWithMissingPassphrase if set to true, missing subkey passphrases will cause the subkey to stay unaffected.
         * @return fixed key ring
         * @throws PGPException in case of a PGP error.
         */
        @JvmStatic
        @JvmOverloads
        fun replaceUsageChecksumWithUsageSha1(
                keys: PGPSecretKeyRing,
                protector: SecretKeyRingProtector,
                skipKeysWithMissingPassphrase: Boolean = false
        ): PGPSecretKeyRing {
            val digestCalculator = ImplementationFactory.getInstance().getPGPDigestCalculator(HashAlgorithm.SHA1)
            val keyList = mutableListOf<PGPSecretKey>()
            for (key in keys) {
                // CHECKSUM is not recommended
                if (key.s2KUsage != SecretKeyPacket.USAGE_CHECKSUM) {
                    keyList.add(key)
                    continue
                }

                val keyId = key.keyID
                val encryptor = protector.getEncryptor(keyId)
                if (encryptor == null) {
                    if (skipKeysWithMissingPassphrase) {
                        keyList.add(key)
                        continue
                    }
                    throw WrongPassphraseException("Missing passphrase for key with ID " + java.lang.Long.toHexString(keyId))
                }

                val privateKey = unlockSecretKey(key, protector)
                // This constructor makes use of USAGE_SHA1 by default
                val fixedKey = PGPSecretKey(
                        privateKey,
                        key.publicKey,
                        digestCalculator,
                        key.isMasterKey,
                        protector.getEncryptor(keyId)
                )
                keyList.add(fixedKey)
            }
            return PGPSecretKeyRing(keyList)
        }
    }
}