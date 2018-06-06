package de.vanitasvitae.crypto.pgpainless;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Collections;

import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.encryption_signing.SecretKeyRingDecryptor;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.length.RsaLength;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class Main {

    public static void main(String[] args)
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {

        Security.addProvider(new BouncyCastleProvider());

        PGPSecretKeyRing a = PGPainless.generateKeyRing().simpleRsaKeyRing("a@b.c", RsaLength._2048);
        PGPSecretKeyRing b = PGPainless.generateKeyRing().simpleRsaKeyRing("b@c.d", RsaLength._2048);

        SecretKeyRingDecryptor secretKeyRingDecryptor = new SecretKeyRingDecryptor() {
            @Override
            public PBESecretKeyDecryptor getDecryptor(Long keyId) {
                return null;
            }

            @Override
            public PBESecretKeyEncryptor getEncryptor(Long keyId) {
                return null;
            }
        };

        byte[] m = "Dies ist ein verschlüsselter Text.".getBytes();
        ByteArrayInputStream fromPlain = new ByteArrayInputStream(m);
        ByteArrayOutputStream toEncrypted = new ByteArrayOutputStream();

        OutputStream encryptor = PGPainless.createEncryptor().onOutputStream(toEncrypted)
                .toRecipient(b.getPublicKey())
                .usingAlgorithms(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA512, CompressionAlgorithm.UNCOMPRESSED)
                .signWith(a.getSecretKey(), secretKeyRingDecryptor)
                .asciiArmor();

        Streams.pipeAll(fromPlain, encryptor);
        fromPlain.close();
        encryptor.close();

        System.out.println(new String(toEncrypted.toByteArray()));

        ByteArrayInputStream fromEncrypted = new ByteArrayInputStream(toEncrypted.toByteArray());
        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();

        PainlessResult.ResultAndInputStream resultAndInputStream  = PGPainless.createDecryptor()
                .onInputStream(fromEncrypted)
                .decryptWith(new PGPSecretKeyRingCollection(Collections.singleton(b)), secretKeyRingDecryptor)
                .verifyWith(Collections.singleton(a.getPublicKey().getKeyID()),
                        Collections.singleton(new PGPPublicKeyRing(a.getPublicKey().getEncoded(), new BcKeyFingerprintCalculator())))
                .ignoreMissingPublicKeys()
                .build();

        InputStream decryptor = resultAndInputStream.getInputStream();

        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();
        toPlain.close();

        PainlessResult result = resultAndInputStream.getResult();

        System.out.println(b.getPublicKey().getKeyID() + " " + result.getDecryptionKeyId());
        System.out.println(new String(toPlain.toByteArray()));
    }

    private static void gpg(PGPSecretKeyRing a, PGPSecretKeyRing b, SecretKeyRingDecryptor secretKeyRingDecryptor)
            throws IOException, PGPException {
        String gpg = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "hQGMAwAAAAAAAAAAAQv+JyovfiPxDiLe9XlgQAG6zD+YdRtZRuUJD+A+ZX4Sn0w0\n" +
                "2Dl9Ehf7lKjIo0cIfVOUrgITnWIRWAyfrk5KiXdXcZ6dXxz/YJFnLSlgqUwq7GWi\n" +
                "NYf3Uqg+/8f3Ucl0x6sr1oddwB9OI7zRJwDqEzTORjLBu1vtDlFPMPWwAeqDtZgz\n" +
                "ikT6vSFfhVjVbgx4mztw7hatWNjXzNkl9+lojzo9IyiA+3SBsRe/2My3ZBjPx97f\n" +
                "3YGMCvbggdX3C/MRV2iek2pFX7YTKasFeEy5Y1c09upqaEIpaJq8vi1Fu44dv0Rt\n" +
                "gv4sdljaJXsFn9aoVFrp/xU4SyPiC1Z/KjqE3Zfyh+OMWKoWmtYH07/g8IGkkBCh\n" +
                "xuDiyy813WS3xtCyX405Vd+rxYC3y1h1FtthdO/AIrYSWj6qI6hyK2tyYmwsg+oY\n" +
                "1oaXhcTbWXsBO89v0YtmVK1bPVXq8ao/DQvrs84JsYsKzXA17gKyBLBUoTNn8h8A\n" +
                "AXg455AN8iHi2u5pAKr7hQIMAwAAAAAAAAAAAQ/7Bg8SGEfMPmtDy/BazrYWaXvX\n" +
                "1+WWRNM630ULPEq7LG4BKJJOOrhk0kNkjIsaXhgqn9bt3YxxuE1eOQksjn0sNOD7\n" +
                "3NAOicHzQ7xOarvN9OUSGirc+EIn4ETRGKYF1TXHBSYnBeb+DLCbRZkBZhRrA5Lc\n" +
                "z08kWrGRfq5Bz6eMatBTO1L8XTIxHPgc9/LNv7OqcIfT0udjOQMkA7oxCz5mLl2b\n" +
                "dApsDEFNKNaGgRzSf2rDqw0SGkDxYsXI6IYrVSEm6uDt+ScybS0KkcEgg+I9l91n\n" +
                "XgqQQaXpYnHgETqKYfcUOk5iEND5Lvik/XhHNViaL3CdOkxFLTa0wfy0y0IsV2Y3\n" +
                "xGkMOWdDjXlY8UWRgoK61M91phgZ48zfSoVvXNDrjOJzm1jn8CFFFov4Gse7CtlM\n" +
                "A+3ntVdjL94jkp+2mU3e9kzCOG+ChylLuqlGTvavbHt/rzuZooi/6g1VHy1r+v9I\n" +
                "rWKX6q55H8JzZXZOrfED39QocK9b1BjtEca/Qnqw82+IVY/CufBmnmbOWUkHq1zP\n" +
                "6nj840HxH1zV5vHf8vlXxV7/iBesAF94dLT/Hp0E7+Ilyp/pQaQjMS2RLycMUJQJ\n" +
                "pQey81gpuOWD6YIbvgnrMBMrJLyJSk3r3sMdJ3DCPxHC+OyvHxddA5TdL2e4aP3L\n" +
                "OzKql59v1w+9Doe3LEPSPgEVAdUUg0nEl5lg9LLqaepaYp8NfsEC1Rnk/MLxciJu\n" +
                "9oNjqPqQxKTv4aQO/Qb8gHFb3O34OnNKz+CzrX5Q\n" +
                "=sVVl\n" +
                "-----END PGP MESSAGE-----";

        ByteArrayInputStream inputStream = new ByteArrayInputStream(gpg.getBytes());

        InputStream decryptor = PGPainless.createDecryptor().onInputStream(inputStream)
                .decryptWith(new PGPSecretKeyRingCollection(Collections.singleton(b)), secretKeyRingDecryptor)
                .doNotVerify()
                .build()
                .getInputStream();

    }

    public static void symm(PGPSecretKeyRing a, PGPSecretKeyRing b, SecretKeyRingDecryptor secretKeyRingDecryptor)
            throws IOException, PGPException {
        byte[] bytes = "Diese Nachricht ist streng geheim!!!".getBytes(Charset.forName("UTF-8"));
        ByteArrayInputStream fromPlain = new ByteArrayInputStream(bytes);
        ByteArrayOutputStream toEncrypted = new ByteArrayOutputStream();

        OutputStream encryptor = PGPainless.createEncryptor()
                .onOutputStream(toEncrypted)
                .toRecipient(b.getPublicKey())
                .usingAlgorithms(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA512, CompressionAlgorithm.UNCOMPRESSED)
                .signWith(a.getSecretKey(), secretKeyRingDecryptor)
                .noArmor();

        Streams.pipeAll(fromPlain, encryptor);
        encryptor.close();

        System.out.println(new String(toEncrypted.toByteArray(), Charset.forName("UTF-8")));

        ByteArrayInputStream fromEncrypted = new ByteArrayInputStream(toEncrypted.toByteArray());
        ByteArrayOutputStream toPlain = new ByteArrayOutputStream();

        PainlessResult.ResultAndInputStream resultAndInputStream = PGPainless.createDecryptor()
                .onInputStream(fromEncrypted)
                .decryptWith(new PGPSecretKeyRingCollection(Collections.singleton(b)), secretKeyRingDecryptor)
                .verifyWith(Collections.singleton(a.getPublicKey().getKeyID()),
                        Collections.singleton(new PGPPublicKeyRing(a.getPublicKey().getEncoded(), new BcKeyFingerprintCalculator())))
                .ignoreMissingPublicKeys()
                .build();

        InputStream decryptor = resultAndInputStream.getInputStream();

        Streams.pipeAll(decryptor, toPlain);
        decryptor.close();

        PainlessResult result = resultAndInputStream.getResult();
    }
}
