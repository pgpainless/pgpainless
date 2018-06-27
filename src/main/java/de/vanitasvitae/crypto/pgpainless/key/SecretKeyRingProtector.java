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
package de.vanitasvitae.crypto.pgpainless.key;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingProtector {

    /**
     * Return a decryptor for the key of id {@code keyId}.
     *
     * @param keyId id of the key
     * @return decryptor for the key
     */
    PBESecretKeyDecryptor getDecryptor(Long keyId);

    /**
     * Return an encryptor for the key of id {@code keyId}.
     *
     * @param keyId id of the key
     * @return encryptor for the key
     * @throws PGPException if the encryptor cannot be created for some reason
     */
    PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException;

}
