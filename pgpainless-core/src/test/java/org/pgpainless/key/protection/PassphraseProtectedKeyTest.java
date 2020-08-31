/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.protection;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.TestKeys;
import org.pgpainless.util.Passphrase;

public class PassphraseProtectedKeyTest {

    /**
     * Protector that holds only the password of cryptie.
     */
    private final PasswordBasedSecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
            KeyRingProtectionSettings.secureDefaultSettings(),
            new SecretKeyPassphraseProvider() {
                @Nullable
                @Override
                public Passphrase getPassphraseFor(Long keyId) {
                    if (keyId == TestKeys.CRYPTIE_KEY_ID) {
                        return new Passphrase(TestKeys.CRYPTIE_PASSWORD.toCharArray());
                    } else {
                        return null;
                    }
                }
            });

    @Test
    public void testReturnsNonNullDecryptorEncryptorForPassword() throws PGPException {
        assertNotNull(protector.getEncryptor(TestKeys.CRYPTIE_KEY_ID));
        assertNotNull(protector.getDecryptor(TestKeys.CRYPTIE_KEY_ID));
    }

    @Test
    public void testReturnsNullDecryptorEncryptorForNoPassword() throws PGPException {
        assertNull(protector.getEncryptor(TestKeys.JULIET_KEY_ID));
        assertNull(protector.getDecryptor(TestKeys.JULIET_KEY_ID));
    }
}
