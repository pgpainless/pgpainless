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
package org.pgpainless.key.selection.key.impl;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.selection.key.SecretKeySelectionStrategy;

/**
 * Key Selection Strategy that only accepts {@link PGPSecretKey}s which are capable of signing.
 */
public class SignatureKeySelectionStrategy extends SecretKeySelectionStrategy {

    private static final Logger LOGGER = Logger.getLogger(SignatureKeySelectionStrategy.class.getName());

    HasAnyKeyFlagSelectionStrategy.SecretKey flagSelector =
            new HasAnyKeyFlagSelectionStrategy.SecretKey(KeyFlag.SIGN_DATA);

    @Override
    public boolean accept(@Nonnull PGPSecretKey key) {
        boolean hasSignDataKeyFlag = flagSelector.accept(key);

        if (!key.isSigningKey()) {
            LOGGER.log(Level.FINE, "Rejecting key " + Long.toHexString(key.getKeyID()) + " as its algorithm (" +
                    PublicKeyAlgorithm.fromId(key.getPublicKey().getAlgorithm()) + ") is not capable of signing.");
            return false;
        }

        if (!hasSignDataKeyFlag) {
            LOGGER.log(Level.FINE, "Rejecting key " + Long.toHexString(key.getKeyID()) +
                    " as it does not carry the key flag SIGN_DATA.");
            return false;
        }
        return true;
    }

}
