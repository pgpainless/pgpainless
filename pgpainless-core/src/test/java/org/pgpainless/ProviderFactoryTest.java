package org.pgpainless;

import static junit.framework.TestCase.assertEquals;

import org.junit.Test;
import org.pgpainless.provider.ProviderFactory;

public class ProviderFactoryTest {

    @Test
    public void providerFactoryDefaultIsBouncyCastleTest() {
        assertEquals("BC", ProviderFactory.getProviderName());
    }
}
