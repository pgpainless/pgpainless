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
package org.pgpainless.key.info;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public abstract class KeyView {

    protected final KeyRingInfo info;
    protected final SubkeyIdentifier key;

    public KeyView(KeyRingInfo info, SubkeyIdentifier key) {
        this.info = info;
        this.key = key;
    }

    public abstract PGPSignature getSignatureWithPreferences();

    public List<SymmetricKeyAlgorithm> getPreferredSymmetricKeyAlgorithms() {
        List<SymmetricKeyAlgorithm> algos = SignatureSubpacketsUtil.parsePreferredSymmetricKeyAlgorithms(getSignatureWithPreferences());
        return new ArrayList<>(new LinkedHashSet<>(algos)); // remove duplicates
    }

    public List<HashAlgorithm> getPreferredHashAlgorithms() {
        List<HashAlgorithm> algos = SignatureSubpacketsUtil.parsePreferredHashAlgorithms(getSignatureWithPreferences());
        return new ArrayList<>(new LinkedHashSet<>(algos)); // remove duplicates
    }

    public List<CompressionAlgorithm> getPreferredCompressionAlgorithms() {
        List<CompressionAlgorithm> algos = SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(getSignatureWithPreferences());
        return new ArrayList<>(new LinkedHashSet<>(algos)); // remove duplicates
    }

    public static class ViaUserId extends KeyView {

        private final String userId;

        public ViaUserId(KeyRingInfo info, SubkeyIdentifier key, String userId) {
            super(info, key);
            this.userId = userId;
        }

        @Override
        public PGPSignature getSignatureWithPreferences() {
            return info.getLatestUserIdCertification(userId);
        }
    }

    public static class ViaKeyId extends KeyView {

        public ViaKeyId(KeyRingInfo info, SubkeyIdentifier key) {
            super(info, key);
        }

        @Override
        public PGPSignature getSignatureWithPreferences() {
            PGPSignature signature = info.getLatestDirectKeySelfSignature();
            if (signature != null) {
                return signature;
            }

            return info.getLatestUserIdCertification(info.getPrimaryUserId());
        }
    }
}
