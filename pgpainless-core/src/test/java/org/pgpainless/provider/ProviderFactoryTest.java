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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Provider;

import org.junit.jupiter.api.Test;

public class ProviderFactoryTest {

    @Test
    public void providerFactoryDefaultIsBouncyCastleTest() {
        assertEquals("BC", ProviderFactory.getProviderName());
    }

    @Test
    public void setCustomProviderTest() {
        ProviderFactory.setFactory(customProviderFactory);
        assertEquals("PL", ProviderFactory.getProviderName());
        // Reset back to BouncyCastle
        ProviderFactory.setFactory(new BouncyCastleProviderFactory());
    }

    private ProviderFactory customProviderFactory = new ProviderFactory() {

        @SuppressWarnings("deprecation")
        Provider provider = new Provider("PL", 1L, "PGPainlessTestProvider") {

        };

        @Override
        protected Provider _getProvider() {
            return provider;
        }

        @Override
        protected String _getProviderName() {
            return provider.getName();
        }
    };
}
