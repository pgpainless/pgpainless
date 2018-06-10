package de.vanitasvitae.crypto.pgpainless;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;

import de.vanitasvitae.crypto.pgpainless.decryption_verification.DecryptionStream;
import de.vanitasvitae.crypto.pgpainless.key.UnprotectedKeysProtector;
import de.vanitasvitae.crypto.pgpainless.util.BCUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;

public class TestKeysTest extends AbstractPGPainlessTest {

    private final PGPSecretKeyRing juliet;
    private final PGPSecretKeyRing romeo;

    public TestKeysTest() throws IOException, PGPException {
        this.juliet = TestKeys.getJulietSecretKeyRing();
        this.romeo = TestKeys.getRomeoSecretKeyRing();
    }

    @Test
    public void keyIdTest() {
        assertEquals(TestKeys.JULIET_KEY_ID, juliet.getSecretKey().getKeyID());
        assertEquals(TestKeys.ROMEO_KEY_ID, romeo.getSecretKey().getKeyID());
    }

    @Test
    public void decryptVerifyTest() throws Exception {
        String encryptedMessage = TestKeys.TEST_MESSAGE_01;

        DecryptionStream decryptor = PGPainless.createDecryptor()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .decryptWith(new PGPSecretKeyRingCollection(Collections.singleton(juliet)), new UnprotectedKeysProtector())
                .verifyWith(
                        Collections.singleton(juliet.getPublicKey().getKeyID()),
                        BCUtil.keyRingsToKeyRingCollection(BCUtil.publicKeyRingFromSecretKeyRing(juliet)))
                .ignoreMissingPublicKeys()
                .build();

        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();
        toPlain.close();

        byte[] expected = TestKeys.TEST_MESSAGE_01_PLAIN.getBytes(Charset.forName("UTF-8"));
        byte[] actual = toPlain.toByteArray();

        assertTrue(Arrays.equals(expected, actual));
    }
}
