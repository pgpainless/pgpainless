package de.vanitasvitae.crypto.pgpainless;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;

public abstract class AbstractPGPainlessTest {

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }
}
