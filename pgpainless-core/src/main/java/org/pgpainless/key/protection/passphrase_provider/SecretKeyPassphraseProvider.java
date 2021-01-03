/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.key.protection.passphrase_provider;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.util.Passphrase;

/**
 * Interface to allow the user to provide a {@link Passphrase} for an encrypted OpenPGP secret key.
 */
public interface SecretKeyPassphraseProvider {

    @Nullable default Passphrase getPassphraseFor(PGPSecretKey secretKey) {
        return getPassphraseFor(secretKey.getKeyID());
    }
    /**
     * Return a passphrase for the given key. If no record has been found, return null.
     * Note: In case of an unprotected secret key, this method must may not return null, but a {@link Passphrase} with
     * a content of null.
     *
     * @param keyId if of the secret key
     * @return passphrase or null, if no passphrase record has been found.
     */
    @Nullable Passphrase getPassphraseFor(Long keyId);
}
