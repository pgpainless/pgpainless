// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
