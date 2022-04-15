// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.signature.builder.HashContextSigner;
import org.pgpainless.util.Passphrase;

public class HashContextSignerTest {

    private static final String message = "Hello, World!\n";
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 62D5 CBED 8BD0 7D3F D167  240D 4364 E4C1 C4ED 8F59\n" +
            "Comment: Sigfried <sig@fri.ed>\n" +
            "\n" +
            "lFgEYlnOkRYJKwYBBAHaRw8BAQdA7Kxn/sPIXo44xnxLBL81G5ghGzMikFc5ib9/\n" +
            "qgJpZSUAAQCZnJN2l/cfWWh4DijBAwFWoVJOCphKhsJEjKxOzWdqMA2DtBVTaWdm\n" +
            "cmllZCA8c2lnQGZyaS5lZD6IjwQTFgoAQQUCYlnOkQkQQ2TkwcTtj1kWIQRi1cvt\n" +
            "i9B9P9FnJA1DZOTBxO2PWQKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAAAd/gEA\n" +
            "kiPFDdMGjZV/7Do/3ox46iCH3N1I3BGmA2Jt8PsYwe0BAKe5ahLzCNAXjBQU4iSD\n" +
            "A4FGipNaG2ZWgAMkdwVjMLEAnF0EYlnOkRIKKwYBBAGXVQEFAQEHQI3n0cWbBh+7\n" +
            "zeuBjMWevsyxLUCExKSj5fxCh/0GuJgAAwEIBwAA/16V22vjZfAvtnUrVtUZQoYZ\n" +
            "E8h87Jzj/XxXFy63I6qoER2IdQQYFgoAHQUCYlnOkQKeAQKbDAUWAgMBAAQLCQgH\n" +
            "BRUKCQgLAAoJEENk5MHE7Y9ZzhsA+gPb2FNutetjrYUSY7BEsk+PPkCXF9W6JZmb\n" +
            "W/zyRxgpAP9zNzpWrO7kKQ0PwMMd3R1F4Rg6GH+vjXsIbd6jT25UBJxYBGJZzpEW\n" +
            "CSsGAQQB2kcPAQEHQPOZhITstSj3cPfsTiBEPhtCrc184fkAjl4s+gSB9ttRAAD/\n" +
            "RVpdc9BhJ/ZXtqQaCBL65h7Uym7i+HExQphHOiuB3iwQOIjVBBgWCgB9BQJiWc6R\n" +
            "Ap4BApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCYlnOkQAKCRDXXcvYX8Ym\n" +
            "crh9AP99WWietGWYs2//FYi0bEAWp6D0HmHP42rvC3qsqyMa8wD8D1Pi2atKwQTP\n" +
            "JAxQFa06cUIw2POE3llaB0MKQXdTVgQACgkQQ2TkwcTtj1mF+gD+OHo68KeGFUi0\n" +
            "VcVV/dx/6ES9GAIf1TI6jEsaU8TPBcMBAOHG+5MMVvyNiVKLA0JgJPF3JXOOEU+5\n" +
            "qiHwlVoGncUM\n" +
            "=431t\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void signContextWithEdDSAKeys() throws PGPException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        signWithKeys(secretKeys);
    }

    @Test
    public void signContextWithRSAKeys() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleRsaKeyRing("Sigfried", RsaLength._3072);
        signWithKeys(secretKeys);
    }

    @Test
    public void signContextWithEcKeys() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("Sigfried");
        signWithKeys(secretKeys);
    }

    private void signWithKeys(PGPSecretKeyRing secretKeys) throws PGPException, NoSuchAlgorithmException, IOException {
        for (HashAlgorithm hashAlgorithm : new HashAlgorithm[] {
                HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512
        }) {
            signFromContext(secretKeys, hashAlgorithm);
        }
    }

    private void signFromContext(PGPSecretKeyRing secretKeys, HashAlgorithm hashAlgorithm) throws PGPException, NoSuchAlgorithmException, IOException {
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);
        long signingKeyId = PGPainless.inspectKeyRing(certificate).getSigningSubkeys().get(0).getKeyID();
        PGPPrivateKey signingKey = UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(signingKeyId), Passphrase.emptyPassphrase());

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream messageIn = new ByteArrayInputStream(messageBytes);

        PGPSignature signature = signMessage(messageBytes, hashAlgorithm, signingKey);
        assertEquals(hashAlgorithm.getAlgorithmId(), signature.getHashAlgorithm());

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(messageIn)
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(certificate)
                        .addVerificationOfDetachedSignature(signature));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
        assertTrue(metadata.isVerified());
    }

    private PGPSignature signMessage(byte[] message, HashAlgorithm hashAlgorithm, PGPPrivateKey signingKey)
            throws NoSuchAlgorithmException, PGPException {
        // Prepare the hash context
        // This would be done by the caller application
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.getAlgorithmName(), new BouncyCastleProvider());
        messageDigest.update(message);

        return HashContextSigner.signHashContext(messageDigest, SignatureType.BINARY_DOCUMENT, signingKey);
    }
}
