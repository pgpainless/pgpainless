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
package org.pgpainless.key.protection;

import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

/**
 * Stub class for API backwards compatibility.
 * @deprecated use {@link CachingSecretKeyRingProtector} instead.
 */
@Deprecated
public class PassphraseMapKeyRingProtector extends CachingSecretKeyRingProtector {

    public PassphraseMapKeyRingProtector(@Nonnull Map<Long, Passphrase> passphrases, @Nonnull KeyRingProtectionSettings protectionSettings, @Nullable SecretKeyPassphraseProvider missingPassphraseCallback) {
        super(passphrases, protectionSettings, missingPassphraseCallback);
    }
}
