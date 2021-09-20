/*
 * Copyright 2018-2020 Paul Schaub.
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
package org.pgpainless.key.generation;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.Passphrase;

public interface KeyRingBuilderInterface<B extends KeyRingBuilderInterface<B>> {

    B setPrimaryKey(@Nonnull KeySpec keySpec);

    default B setPrimaryKey(@Nonnull KeySpecBuilder builder) {
        return setPrimaryKey(builder.build());
    }

    B addSubkey(@Nonnull KeySpec keySpec);

    default B addSubkey(@Nonnull KeySpecBuilder builder) {
        return addSubkey(builder.build());
    }

    default B addUserId(UserId userId) {
        return addUserId(userId.toString());
    }

    B addUserId(@Nonnull String userId);

    B addUserId(@Nonnull byte[] userId);

    B setExpirationDate(@Nonnull Date expirationDate);

    B setPassphrase(@Nonnull Passphrase passphrase);

    PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException,
                InvalidAlgorithmParameterException;
}
