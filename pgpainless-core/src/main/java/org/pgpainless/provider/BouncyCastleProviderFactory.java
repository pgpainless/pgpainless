/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.provider;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class BouncyCastleProviderFactory extends ProviderFactory {

    private static final Provider provider = new BouncyCastleProvider();

    @Override
    public Provider _getProvider() {
        return provider;
    }

    @Override
    public String _getProviderName() {
        return _getProvider().getName();
    }
}
