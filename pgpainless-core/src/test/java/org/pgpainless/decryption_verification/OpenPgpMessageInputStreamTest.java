package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.COMP;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.COMP_COMP_LIT;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.COMP_LIT;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.LIT;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.LIT_LIT;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.PASSPHRASE;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.PLAINTEXT;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.SENC_LIT;
import static org.pgpainless.decryption_verification.PGPDecryptionStreamTest.SIG_LIT;

public class OpenPgpMessageInputStreamTest {

    @Test
    public void testProcessLIT() throws IOException, PGPException {
        String plain = process(LIT, ConsumerOptions.get());
        assertEquals(PLAINTEXT, plain);
    }

    @Test
    public void testProcessLIT_LIT_fails() {
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> process(LIT_LIT, ConsumerOptions.get()));
    }

    @Test
    public void testProcessCOMP_LIT() throws PGPException, IOException {
        String plain = process(COMP_LIT, ConsumerOptions.get());
        assertEquals(PLAINTEXT, plain);
    }

    @Test
    public void testProcessCOMP_fails() {
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> process(COMP, ConsumerOptions.get()));
    }

    @Test
    public void testProcessCOMP_COMP_LIT() throws PGPException, IOException {
        String plain = process(COMP_COMP_LIT, ConsumerOptions.get());
        assertEquals(PLAINTEXT, plain);
    }

    @Test
    public void testProcessSIG_LIT() throws PGPException, IOException {
        String plain = process(SIG_LIT, ConsumerOptions.get());
        assertEquals(PLAINTEXT, plain);
    }

    @Test
    public void testProcessSENC_LIT() throws PGPException, IOException {
        String plain = process(SENC_LIT, ConsumerOptions.get().addDecryptionPassphrase(Passphrase.fromPassword(PASSPHRASE)));
        assertEquals(PLAINTEXT, plain);
    }

    private String process(String armoredMessage, ConsumerOptions options) throws PGPException, IOException {
        OpenPgpMessageInputStream in = get(armoredMessage, options);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(in, out);
        in.close();
        return out.toString();
    }

    private OpenPgpMessageInputStream get(String armored, ConsumerOptions options) throws IOException, PGPException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        OpenPgpMessageInputStream pgpIn = new OpenPgpMessageInputStream(armorIn, options);
        return pgpIn;
    }
}
