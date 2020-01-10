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

public abstract class ProviderFactory {

    private static ProviderFactory FACTORY = new BouncyCastleProviderFactory();

    protected abstract Provider _getProvider();
    protected abstract String _getProviderName();

    public static void setFactory(ProviderFactory factory) {
        ProviderFactory.FACTORY = factory;
    }

    public static Provider getProvider() {
        return ProviderFactory.FACTORY._getProvider();
    }

    public static String getProviderName() {
        return ProviderFactory.FACTORY._getProviderName();
    }

}
