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
package org.pgpainless.policy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public final class Policy {

    private static Policy INSTANCE;

    private HashAlgorithmPolicy signatureHashAlgorithmPolicy =
            HashAlgorithmPolicy.defaultSignatureAlgorithmPolicy();
    private HashAlgorithmPolicy revocationSignatureHashAlgorithmPolicy =
            HashAlgorithmPolicy.defaultRevocationSignatureHashAlgorithmPolicy();
    private SymmetricKeyAlgorithmPolicy symmetricKeyAlgorithmPolicy =
            SymmetricKeyAlgorithmPolicy.defaultSymmetricKeyAlgorithmPolicy();

    private Policy() {
    }

    public static Policy getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new Policy();
        }
        return INSTANCE;
    }

    public HashAlgorithmPolicy getSignatureHashAlgorithmPolicy() {
        return signatureHashAlgorithmPolicy;
    }

    public void setSignatureHashAlgorithmPolicy(HashAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.signatureHashAlgorithmPolicy = policy;
    }

    public HashAlgorithmPolicy getRevocationSignatureHashAlgorithmPolicy() {
        return revocationSignatureHashAlgorithmPolicy;
    }

    public void setRevocationSignatureHashAlgorithmPolicy(HashAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.revocationSignatureHashAlgorithmPolicy = policy;
    }

    public SymmetricKeyAlgorithmPolicy getSymmetricKeyAlgorithmPolicy() {
        return symmetricKeyAlgorithmPolicy;
    }

    public void setSymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithmPolicy policy) {
        if (policy == null) {
            throw new NullPointerException("Policy cannot be null.");
        }
        this.symmetricKeyAlgorithmPolicy = policy;
    }

    public static final class SymmetricKeyAlgorithmPolicy {

        private final SymmetricKeyAlgorithm defaultSymmetricKeyAlgorithm;
        private final List<SymmetricKeyAlgorithm> acceptableSymmetricKeyAlgorithms;

        public SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm defaultSymmetricKeyAlgorithm, List<SymmetricKeyAlgorithm> acceptableSymmetricKeyAlgorithms) {
            this.defaultSymmetricKeyAlgorithm = defaultSymmetricKeyAlgorithm;
            this.acceptableSymmetricKeyAlgorithms = Collections.unmodifiableList(acceptableSymmetricKeyAlgorithms);
        }

        public SymmetricKeyAlgorithm getDefaultSymmetricKeyAlgorithm() {
            return defaultSymmetricKeyAlgorithm;
        }

        public boolean isAcceptable(SymmetricKeyAlgorithm algorithm) {
            return acceptableSymmetricKeyAlgorithms.contains(algorithm);
        }

        public boolean isAcceptable(int algorithmId) {
            SymmetricKeyAlgorithm algorithm = SymmetricKeyAlgorithm.fromId(algorithmId);
            return isAcceptable(algorithm);
        }

        public static SymmetricKeyAlgorithmPolicy defaultSymmetricKeyAlgorithmPolicy() {
            return new SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256, Arrays.asList(
                    SymmetricKeyAlgorithm.IDEA,
                    SymmetricKeyAlgorithm.CAST5,
                    SymmetricKeyAlgorithm.BLOWFISH,
                    SymmetricKeyAlgorithm.AES_128,
                    SymmetricKeyAlgorithm.AES_192,
                    SymmetricKeyAlgorithm.AES_256,
                    SymmetricKeyAlgorithm.TWOFISH,
                    SymmetricKeyAlgorithm.CAMELLIA_128,
                    SymmetricKeyAlgorithm.CAMELLIA_192,
                    SymmetricKeyAlgorithm.CAMELLIA_256
            ));
        }
    }

    public static final class HashAlgorithmPolicy {

        private final HashAlgorithm defaultHashAlgorithm;
        private final List<HashAlgorithm> acceptableHashAlgorithms;

        public HashAlgorithmPolicy(HashAlgorithm defaultHashAlgorithm, List<HashAlgorithm> acceptableHashAlgorithms) {
            this.defaultHashAlgorithm = defaultHashAlgorithm;
            this.acceptableHashAlgorithms = Collections.unmodifiableList(acceptableHashAlgorithms);
        }

        public HashAlgorithm defaultHashAlgorithm() {
            return defaultHashAlgorithm;
        }

        public boolean isAcceptable(HashAlgorithm hashAlgorithm) {
            return acceptableHashAlgorithms.contains(hashAlgorithm);
        }

        public boolean isAcceptable(int algorithmId) {
            HashAlgorithm algorithm = HashAlgorithm.fromId(algorithmId);
            return isAcceptable(algorithm);
        }

        public static HashAlgorithmPolicy defaultSignatureAlgorithmPolicy() {
            return new HashAlgorithmPolicy(HashAlgorithm.SHA512, Arrays.asList(
                    HashAlgorithm.SHA224,
                    HashAlgorithm.SHA256,
                    HashAlgorithm.SHA384,
                    HashAlgorithm.SHA512
            ));
        }

        public static HashAlgorithmPolicy defaultRevocationSignatureHashAlgorithmPolicy() {
            return new HashAlgorithmPolicy(HashAlgorithm.SHA512, Arrays.asList(
                    HashAlgorithm.RIPEMD160,
                    HashAlgorithm.SHA1,
                    HashAlgorithm.SHA224,
                    HashAlgorithm.SHA256,
                    HashAlgorithm.SHA384,
                    HashAlgorithm.SHA512
            ));
        }
    }
}
