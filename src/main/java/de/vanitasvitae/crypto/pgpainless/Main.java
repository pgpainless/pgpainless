package de.vanitasvitae.crypto.pgpainless;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.KeyFlag;
import de.vanitasvitae.crypto.pgpainless.key.generation.KeySpec;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.DSA;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.RSA_GENERAL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class Main {

    public static void main(String[] args)
            throws NoSuchAlgorithmException, PGPException, NoSuchProviderException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .generateCompositeKeyRing()
                .withSubKey(
                        KeySpec.getBuilder()
                                .ofType(RSA_GENERAL._4096)
                                .withKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                                .withStandardConfiguration())
                .done()
                .withCertificationKeyType(
                        KeySpec.getBuilder()
                                .ofType(DSA._3072)
                                .withKeyFlags(KeyFlag.SIGN_DATA)
                                .withStandardConfiguration())
                .withPrimaryUserId("Test123")
                .done()
                .withoutPassphrase()
                .build();

        byte[] base64 = Base64.getEncoder().encode(secretKeys.getEncoded());

        System.out.println(new String(base64));
    }
}
