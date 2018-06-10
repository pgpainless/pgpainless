package de.vanitasvitae.crypto.pgpainless;

import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import de.vanitasvitae.crypto.pgpainless.key.UnprotectedKeysProtector;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.length.RsaLength;
import de.vanitasvitae.crypto.pgpainless.util.BCUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.Ignore;
import org.junit.Test;

public class EncryptDecryptTest extends AbstractPGPainlessTest {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    @Test
    public void freshRsaTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing aliceSec = PGPainless.generateKeyRing().simpleRsaKeyRing("alice@wonderland.lit", RsaLength._4096);
        PGPSecretKeyRing hatterSec = PGPainless.generateKeyRing().simpleRsaKeyRing("hatter@wonderland.lit", RsaLength._4096);

        encryptDecryptForSecretKeyRings(aliceSec, hatterSec);
    }

    @Test
    public void freshEcTest() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        PGPSecretKeyRing aliceSec = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");
        PGPSecretKeyRing hatterSec = PGPainless.generateKeyRing().simpleEcKeyRing("hatter@wonderland.lit");

        encryptDecryptForSecretKeyRings(aliceSec, hatterSec);
    }

    @Test
    public void freshRsaEcTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing aliceSec = PGPainless.generateKeyRing().simpleRsaKeyRing("alice@wonderland.lit", RsaLength._4096);
        PGPSecretKeyRing hatterSec = PGPainless.generateKeyRing().simpleEcKeyRing("hatter@wonderland.lit");

        encryptDecryptForSecretKeyRings(aliceSec, hatterSec);
    }

    @Test
    public void freshEcRsaTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPSecretKeyRing aliceSec = PGPainless.generateKeyRing().simpleEcKeyRing("alice@wonderland.lit");
        PGPSecretKeyRing hatterSec = PGPainless.generateKeyRing().simpleRsaKeyRing("hatter@wonderland.lit", RsaLength._4096);


        encryptDecryptForSecretKeyRings(aliceSec, hatterSec);
    }

    @Ignore
    private void encryptDecryptForSecretKeyRings(PGPSecretKeyRing aliceSec, PGPSecretKeyRing hatterSec)
            throws PGPException,
            IOException {
        PGPPublicKeyRing alicePub = BCUtil.publicKeyRingFromSecretKeyRing(aliceSec);
        PGPPublicKeyRing hatterPub = BCUtil.publicKeyRingFromSecretKeyRing(hatterSec);

        SecretKeyRingProtector keyDecryptor = new UnprotectedKeysProtector();

        byte[] secretMessage = ("Ah, Juliet, if the measure of thy joy\n" +
                "Be heaped like mine, and that thy skill be more\n" +
                "To blazon it, then sweeten with thy breath\n" +
                "This neighbor air, and let rich music’s tongue\n" +
                "Unfold the imagined happiness that both\n" +
                "Receive in either by this dear encounter.").getBytes(UTF8);

        Logger.getLogger(EncryptDecryptTest.class.getName())
                .log(Level.INFO, " " + secretMessage.length);

        ByteArrayOutputStream envelope = new ByteArrayOutputStream();

        OutputStream encryptor = PGPainless.createEncryptor()
                .onOutputStream(envelope)
                .toRecipients(Collections.singleton(alicePub))
                .usingSecureAlgorithms()
                .signWith(hatterSec, keyDecryptor)
                .noArmor();

        Streams.pipeAll(new ByteArrayInputStream(secretMessage), encryptor);
        encryptor.close();
        byte[] encryptedSecretMessage = envelope.toByteArray();

        // Juliet trieth to comprehend Romeos words

        ByteArrayInputStream envelopeIn = new ByteArrayInputStream(encryptedSecretMessage);
        PainlessResult.ResultAndInputStream resultAndInputStream = PGPainless.createDecryptor()
                .onInputStream(envelopeIn)
                .decryptWith(BCUtil.keyRingsToKeyRingCollection(aliceSec), keyDecryptor)
                .verifyWith(Collections.singleton(TestKeys.ROMEO_KEY_ID), BCUtil.keyRingsToKeyRingCollection(hatterPub))
                .ignoreMissingPublicKeys()
                .build();

        InputStream decryptor = resultAndInputStream.getInputStream();
        OutputStream decryptedSecretMessage = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decryptedSecretMessage);
        decryptor.close();

        assertTrue(Arrays.equals(secretMessage, ((ByteArrayOutputStream) decryptedSecretMessage).toByteArray()));

        PainlessResult result = resultAndInputStream.getResult();
        assertTrue(result.containsVerifiedSignatureFrom(hatterPub));
    }
}
