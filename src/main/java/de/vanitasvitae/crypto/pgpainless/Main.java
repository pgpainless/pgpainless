package de.vanitasvitae.crypto.pgpainless;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class Main {

    public static void main(String[] args)
            throws NoSuchAlgorithmException, PGPException, NoSuchProviderException, IOException,
            InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());

        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("elliptic@cur.ve");

        //System.out.println(Base64.getEncoder().encodeToString(secretKeys.getEncoded()));
    }
}
