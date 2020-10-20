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

import javax.annotation.Nonnull;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.util.Passphrase;

public interface KeyRingBuilderInterface {

    KeyRingBuilderInterface withSubKey(@Nonnull KeySpec keySpec);

    WithPrimaryUserId withMasterKey(@Nonnull KeySpec keySpec);

    interface WithPrimaryUserId {

        WithAdditionalUserIdOrPassphrase withPrimaryUserId(@Nonnull String userId);

        WithAdditionalUserIdOrPassphrase withPrimaryUserId(@Nonnull byte[] userId);

    }

    interface WithAdditionalUserIdOrPassphrase {

        WithAdditionalUserIdOrPassphrase withAdditionalUserId(@Nonnull String userId);

        WithAdditionalUserIdOrPassphrase withAdditionalUserId(@Nonnull byte[] userId);

        Build withPassphrase(@Nonnull Passphrase passphrase);

        Build withoutPassphrase();
    }

    interface Build {

        PGPKeyRing build() throws NoSuchAlgorithmException, PGPException,
                InvalidAlgorithmParameterException;

    }
}
