/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.protection.fixes;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

/**
 * Repair class to fix keys which use S2K usage of value {@link SecretKeyPacket#USAGE_CHECKSUM}.
 * The method {@link #replaceUsageChecksumWithUsageSha1(PGPSecretKeyRing, SecretKeyRingProtector)} ensures
 * that such keys are encrypted using S2K usage {@link SecretKeyPacket#USAGE_SHA1} instead.
 *
 * @see <a href="https://github.com/pgpainless/pgpainless/issues/176">Related PGPainless Bug Report</a>
 * @see <a href="https://github.com/pgpainless/pgpainless/issues/178">Related PGPainless Feature Request</a>
 * @see <a href="https://github.com/bcgit/bc-java/issues/1020">Related upstream BC bug report</a>
 */
public final class S2KUsageFix {

    private S2KUsageFix() {

    }

    /**
     * Repair method for keys which use S2K usage <pre>USAGE_CHECKSUM</pre> which is deemed insecure.
     * This method fixes the private keys by changing them to <pre>USAGE_SHA1</pre> instead.
     *
     * @param keys keys
     * @param protector protector to unlock and re-lock affected private keys
     * @return fixed key ring
     * @throws PGPException in case of a PGP error.
     */
    public static PGPSecretKeyRing replaceUsageChecksumWithUsageSha1(PGPSecretKeyRing keys, SecretKeyRingProtector protector) throws PGPException {
        return replaceUsageChecksumWithUsageSha1(keys, protector, false);
    }

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
    public static PGPSecretKeyRing replaceUsageChecksumWithUsageSha1(PGPSecretKeyRing keys,
                                                                     SecretKeyRingProtector protector,
                                                                     boolean skipKeysWithMissingPassphrase) throws PGPException {
        PGPDigestCalculator digestCalculator = ImplementationFactory.getInstance().getPGPDigestCalculator(HashAlgorithm.SHA1);
        for (PGPSecretKey key : keys) {
            // CHECKSUM is not recommended
            if (key.getS2KUsage() != SecretKeyPacket.USAGE_CHECKSUM) {
                continue;
            }

            long keyId = key.getKeyID();
            PBESecretKeyEncryptor encryptor = protector.getEncryptor(keyId);
            if (encryptor == null) {
                if (skipKeysWithMissingPassphrase) {
                    continue;
                }
                throw new WrongPassphraseException("Missing passphrase for key with ID " + Long.toHexString(keyId));
            }

            PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(key, protector);
            // This constructor makes use of USAGE_SHA1 by default
            PGPSecretKey fixedKey = new PGPSecretKey(
                    privateKey,
                    key.getPublicKey(),
                    digestCalculator,
                    key.isMasterKey(),
                    protector.getEncryptor(keyId)
            );

            // replace the original key with the fixed one
            keys = PGPSecretKeyRing.insertSecretKey(keys, fixedKey);
        }
        return keys;
    }
}
