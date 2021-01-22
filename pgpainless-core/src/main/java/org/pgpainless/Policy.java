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
package org.pgpainless;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public final class Policy {

    private static Policy INSTANCE;

    private HashAlgorithm signatureHashAlgorithm = HashAlgorithm.SHA512;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_256;

    private Policy() {
    }

    public static Policy getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new Policy();
        }
        return INSTANCE;
    }

    public void setDefaultSignatureHashAlgorithm(HashAlgorithm hashAlgorithm) {
        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("HashAlgorithm cannot be null.");
        }
        this.signatureHashAlgorithm = hashAlgorithm;
    }

    public HashAlgorithm getDefaultSignatureHashAlgorithm() {
        return signatureHashAlgorithm;
    }

    public void setDefaultKeyEncryptionAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
    }

    public SymmetricKeyAlgorithm getDefaultSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }
}
