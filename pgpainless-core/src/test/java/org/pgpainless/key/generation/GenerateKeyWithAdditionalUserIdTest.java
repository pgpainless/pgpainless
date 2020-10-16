package org.pgpainless.key.generation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.RSA_SIGN;
import org.pgpainless.key.generation.type.length.RsaLength;

public class GenerateKeyWithAdditionalUserIdTest {

    @Test
    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing()
                .withMasterKey(KeySpec.getBuilder(RSA_SIGN.withLength(RsaLength._3072))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId("primary@user.id")
                .withAdditionalUserId("additional@user.id")
                .withoutPassphrase()
                .build();

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(byteOut);
        keyRing.getSecretKeys().encode(armor);
        armor.close();

        System.out.println(byteOut.toString("UTF-8"));
    }
}
