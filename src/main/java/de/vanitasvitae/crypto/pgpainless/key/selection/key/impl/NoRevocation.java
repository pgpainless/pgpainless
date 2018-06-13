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
package de.vanitasvitae.crypto.pgpainless.key.selection.key.impl;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * Key Selection Strategies that do accept only keys, which have no revocation.
 */
public class NoRevocation {

    /**
     * Key Selection Strategy which only accepts {@link PGPPublicKey}s which have no revocation.
     *
     * @param <O> Type that describes the owner of this key (not used for this decision).
     */
    public static class PubKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPPublicKey key) {
            return !key.hasRevocation();
        }
    }

    /**
     * Key Selection Strategy which only accepts {@link PGPSecretKey}s which have no revocation.
     *
     * @param <O> Type that describes the owner of this key (not used for this decision).
     */
    public static class SecKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPSecretKey key) {
            return !key.getPublicKey().hasRevocation();
        }
    }
}
