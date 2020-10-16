package org.pgpainless.key.generation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRing;
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

        Iterator<String> userIds = keyRing.getPublicKeys().getPublicKey().getUserIDs();
        assertEquals("primary@user.id", userIds.next());
        assertEquals("additional@user.id", userIds.next());
        assertFalse(userIds.hasNext());

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(byteOut);
        keyRing.getSecretKeys().encode(armor);
        armor.close();

        // echo this | gpg --list-packets
        System.out.println(byteOut.toString("UTF-8"));
    }
}
