package de.vanitasvitae.crypto.pgpainless;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;

import de.vanitasvitae.crypto.pgpainless.key.UnprotectedKeysProtector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;

public class EncryptDecryptTest {
    PGPSecretKeyRing juliet = new PGPSecretKeyRing(PGPUtil.getDecoderStream(new ByteArrayInputStream(TestKeys.JULIET_PRIV.getBytes())), new BcKeyFingerprintCalculator());
    PGPSecretKeyRing romeo = new PGPSecretKeyRing(PGPUtil.getDecoderStream(new ByteArrayInputStream(TestKeys.ROMEO_PRIV.getBytes())), new BcKeyFingerprintCalculator());

    public EncryptDecryptTest() throws IOException, PGPException {

    }

    @Test
    public void keyIdTest() {
        assertEquals("b4b509cb5936e03e", Long.toHexString(juliet.getSecretKey().getKeyID()));
    }

    @Test
    public void test() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PGPPublicKeyRing jPub = new PGPPublicKeyRing(PGPUtil.getDecoderStream(new ByteArrayInputStream(TestKeys.JULIET_PUB.getBytes())), new BcKeyFingerprintCalculator());

        ByteArrayOutputStream toEncrypted = new ByteArrayOutputStream();

        OutputStream encryptor = PGPainless.createEncryptor().onOutputStream(toEncrypted)
                .toRecipient(jPub.getPublicKey())
                .usingSecureAlgorithms()
                .signWith(new PGPSecretKeyRing(PGPUtil.getDecoderStream(new ByteArrayInputStream(TestKeys.JULIET_PRIV.getBytes())), new BcKeyFingerprintCalculator()), new UnprotectedKeysProtector())
                .asciiArmor();

        String message = "This message is encrypted using OpenPGP";
        ByteArrayInputStream fromPlain = new ByteArrayInputStream(message.getBytes());

        Streams.pipeAll(fromPlain, encryptor);
        fromPlain.close();
        encryptor.close();

        System.out.println(new String(toEncrypted.toByteArray()));


        ByteArrayInputStream fromEncrypted = new ByteArrayInputStream(toEncrypted.toByteArray());
        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();

        PainlessResult.ResultAndInputStream resultAndInputStream = PGPainless.createDecryptor()
                .onInputStream(fromEncrypted)
                .decryptWith(new PGPSecretKeyRingCollection(Collections.singleton(juliet)),
                        new UnprotectedKeysProtector())
                .verifyWith(Collections.singleton(jPub.getPublicKey().getKeyID()), Collections.singleton(jPub))
                .ignoreMissingPublicKeys()
                .build();

        InputStream decryptor = resultAndInputStream.getInputStream();

        Streams.pipeAll(decryptor, toPlain);

        fromEncrypted.close();
        decryptor.close();

        assertTrue(Arrays.equals(message.getBytes(), toPlain.toByteArray()));
    }

    @Test
    public void decryptVerifyTest() throws Exception {
        String encryptedMessage = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "hQGMAwAAAAAAAAAAAQwAoJtfpcBPCwhUzzHuVIcBzBLyfIWT/EJ527neb46lN56S\n" +
                "B05BTIRudIeCsPYz81jwiFi/k0MBecRfozZ1xCPByo8ohSvRgzEHEkCNgObQ1bz0\n" +
                "iB+Xb76OEzFOCPUebTaVscLNf8ak/GSzaW7jDc+5vnvDf7cV0x26pe4odpS/U5Tr\n" +
                "cO3wb/47K+sJ1cxJmPtcD41O02xu3QisQKPrimM0Kue6ziGeKyw1RkSowv9U47TK\n" +
                "wppPCHOTli2Nf+gZizF1oyQZzPGst4fjujygcIoajplfW9nZvxsbmYRSLSdmV9m6\n" +
                "k1jQbPDUhVs0gstH92C6hPpoBWxoxkHcwz8gy36nCyB6cYGyq3oN1UnGU4afPyD5\n" +
                "SmmEjELBd2i2Ll/DYk2x06SnKZMQuWrSCZzWgl/9HsPo5ydVb97OjuEpWtW9xDMA\n" +
                "KlYPNWEq+b+akOEstNraC3pfVKvypz6ZzaMAS1gWWNYg8dlwBJOUVMSo7iLaUQkK\n" +
                "yp4uH1DlsyVu1atCUc8thQIMAwAAAAAAAAAAAQ/5AdiZ/sG859Y/rGR7U/8MzGg0\n" +
                "j3f2vrgDF/0NRRk5aqd1lb4CaZvrztcYqW3cEK7iF9rKwImZZiWIptjJ9Mz6f1Zl\n" +
                "FbODObSVRZAcZqYGswEEfsQvpQFlwG6Qx48OaQaDPr147raFI3C3kEU9Nb2VBg8+\n" +
                "MevJaXJft5PXwUTG2Qvfxqr/3hfGAwB4/zHwA8vFd1np3spryfrC9Dq8UXUoRXIS\n" +
                "xaFPiLEYt8rLef8f11OypEpmknIibu9jjJtuVZo+SjP6jgLHDwM7rqCZFITM2Qra\n" +
                "2iBCt8YVcIiTK137t+EfsdVN/KHiRbc++e9zUbGMEextbtNbdoFOU4dnKBm6Su8l\n" +
                "Z5UerNbR8D7+xJKfAEabdi0qI7QFmhTZ/4H/22yrvoD9jMFSBXUTE9ENIX9Hfqom\n" +
                "UdsHfuE+5PC0JjkZkhchDO1M7XBX++lBCFsq2abfdpmaX+roVX0iTGboxr5Ag1Cf\n" +
                "T2zWyRX/XKnvmdeGICV5qjy/ThuSWvAclazyFxWLamMztJq5BRpfAzKNQRDqlmKw\n" +
                "eePtKW2EWUIjFQ5/UAM6Edu/K34ksFxb0w6YGLzQSskGr7gGAipLmpek6vcUSUA1\n" +
                "oc9XJGdpx93GDRcqDjKDt/ej06VxG33/pW65ntf5QM/+LScGqaLhAHyEOsBzVIXY\n" +
                "BONcadSgzkTrlbSMGAmFAQwDtLUJy1k24D4BB/0brqR0UN1LtO+Lc/vN6X/Um2CZ\n" +
                "CM6MRhPnXP63Q9HHkGJ2S8zGWvQLwWL9Y14CFCgm6rACLBSIyPbihhC2OC8afhSy\n" +
                "apGkdHtdghS2egs2U8qlJ2Y32IAG9CcUtNkRjxp+/RWSrmZeuL4l7DXCyH5lUadx\n" +
                "5bPZhAHqW9408q2rQd9dBg2o7ciGXTJSKVahjuiB/O0gchOnbqnlYJbKbCkntXUo\n" +
                "c7h4w1e8MutisSJorh7kbxgxUJSboZzEkiUfnoacPTz6bL+re9tmnpvlee70sIyM\n" +
                "BiYRCyPw7Ice4R3XyWtsMTjT/wjZ//whMpWdy2drcJSyhh+GQMbekTVsNWod0lQB\n" +
                "JTPUfti2VU7PMB3LjJA+l/T9iWPPx8lirnLhXOOerWKH9I5Wo4Kqv/47aJhfMO6+\n" +
                "jmLekAOylq+9DizrslW/EUgQyjIbcWfmyMiV6E2RwbI93tE=\n" +
                "=GAhR\n" +
                "-----END PGP MESSAGE-----";

        PainlessResult.ResultAndInputStream resultAndInputStream = PGPainless.createDecryptor()
                .onInputStream(new ByteArrayInputStream(encryptedMessage.getBytes()))
                .decryptWith(new PGPSecretKeyRingCollection(Collections.singleton(juliet)), new UnprotectedKeysProtector())
                .verifyWith(
                        Collections.singleton(juliet.getPublicKey().getKeyID()),
                        Collections.singleton(
                                new PGPPublicKeyRing(
                                        PGPUtil.getDecoderStream(new ByteArrayInputStream(TestKeys.JULIET_PUB.getBytes())),
                                        new BcKeyFingerprintCalculator())))
                .ignoreMissingPublicKeys()
                .build();

        InputStream decryptor = resultAndInputStream.getInputStream();
        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();
        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();
        toPlain.close();

        byte[] expected = "This message is encrypted\n".getBytes(Charset.forName("UTF-8"));
        byte[] actual = toPlain.toByteArray();

        assertTrue(Arrays.equals(expected, actual));
    }
}
