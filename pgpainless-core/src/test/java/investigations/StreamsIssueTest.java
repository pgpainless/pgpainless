/*
 * Copyright (c) 2023. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package investigations;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import java.util.UUID;

import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.mail.BodyPart;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.MissingKeyPassphraseStrategy;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class StreamsIssueTest {
    private static final String SENDER_PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "lIYEYIq7phYJKwYBBAHaRw8BAQdAat45rrh+gvQwWwJw5eScq3Pdxt/8d+lWNVSm\n" +
            "kImXcRP+CQMCvWfx3mzDdd5g6c59LcPqADK0p70/7ZmTkp3ZC1YViTprg4tQt/PF\n" +
            "QJL+VPCG+BF9bWyFcfxKe+KAnXRTWml5O6xrv6ZkiNmAxoYyO1shzLQWZGVmYXVs\n" +
            "dEBmbG93Y3J5cHQudGVzdIh4BBMWCgAgBQJgirumAhsDBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCHgECGQEACgkQIl+AI8INCVcysgD/cu23M07rImuV5gIl98uOnSIR+QnHUD/M\n" +
            "I34b7iY/iTQBALMIsqO1PwYl2qKwmXb5lSoMj5SmnzRRE2RwAFW3AiMCnIsEYIq7\n" +
            "phIKKwYBBAGXVQEFAQEHQA8q7iPr+0OXqBGBSAL6WNDjzHuBsG7uiu5w8l/A6v8l\n" +
            "AwEIB/4JAwK9Z/HebMN13mCOF6Wy/9oZK4d0DW9cNLuQDeRVZejxT8oFMm7G8iGw\n" +
            "CGNjIWWcQSvctBZtHwgcMeplCW7tmzkD3Nq/ty50lCwQQd6gZSXMiHUEGBYKAB0F\n" +
            "AmCKu6YCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRAiX4Ajwg0JV+sbAQCv4LVM\n" +
            "0+AN54ivWa4vPRyYOfSQ1FqsipkYLJce+xwUeAD+LZpEVCypFtGWQVdeSJVxIHx3\n" +
            "k40IfHsK0fGgR+NrRAw=\n" +
            "=osuI\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String SENDER_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "mDMEYIq7phYJKwYBBAHaRw8BAQdAat45rrh+gvQwWwJw5eScq3Pdxt/8d+lWNVSm\n" +
            "kImXcRO0FmRlZmF1bHRAZmxvd2NyeXB0LnRlc3SIeAQTFgoAIAUCYIq7pgIbAwUW\n" +
            "AgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJECJfgCPCDQlXMrIA/3LttzNO6yJrleYC\n" +
            "JffLjp0iEfkJx1A/zCN+G+4mP4k0AQCzCLKjtT8GJdqisJl2+ZUqDI+Upp80URNk\n" +
            "cABVtwIjArg4BGCKu6YSCisGAQQBl1UBBQEBB0APKu4j6/tDl6gRgUgC+ljQ48x7\n" +
            "gbBu7orucPJfwOr/JQMBCAeIdQQYFgoAHQUCYIq7pgIbDAUWAgMBAAQLCQgHBRUK\n" +
            "CQgLAh4BAAoJECJfgCPCDQlX6xsBAK/gtUzT4A3niK9Zri89HJg59JDUWqyKmRgs\n" +
            "lx77HBR4AP4tmkRULKkW0ZZBV15IlXEgfHeTjQh8ewrR8aBH42tEDA==\n" +
            "=kdDK\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String RECEIVER_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "mDMEYIucWBYJKwYBBAHaRw8BAQdAew+8mzMWyf3+Pfy49qa60uKV6e5os7de4TdZ\n" +
            "ceAWUq+0F2RlbmJvbmQ3QGZsb3djcnlwdC50ZXN0iHgEExYKACAFAmCLnFgCGwMF\n" +
            "FgIDAQAECwkIBwUVCgkICwIeAQIZAQAKCRDDIInNavjWzm3JAQCgFgCEyD58iEa/\n" +
            "Rw/DYNoQNoZC1lhw1bxBiOcIbtkdBgEAsDFZu3TBavOMKI7KW+vfMBHtRVbkMNpv\n" +
            "unaAldoabgO4OARgi5xYEgorBgEEAZdVAQUBAQdAB1/Mrq5JGYim4KqGTSK4OESQ\n" +
            "UwPgK56q0yrkiU9WgyYDAQgHiHUEGBYKAB0FAmCLnFgCGwwFFgIDAQAECwkIBwUV\n" +
            "CgkICwIeAQAKCRDDIInNavjWzjMgAQCU+R1fItqdY6lt9jXUqipmXuqVaEFPwNA8\n" +
            "YJ1rIwDwVQEAyUc8162KWzA2iQB5akwLwNr/pLDDtOWwhLUkrBb3mAc=\n" +
            "=pXF6\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String PASSPHRASE = "android";

    @Test
    public void successStreamsUsageTest() throws MessagingException, PGPException, IOException {
        MimeMessage mimeMessage = prepareMimeMessage("text.txt", "text/plain");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        assertDoesNotThrow(() -> mimeMessage.writeTo(byteArrayOutputStream));
        String rawMimeMessage = byteArrayOutputStream.toString();
        assertNotNull(rawMimeMessage);
    }

    @Test
    public void failedStreamsUsageTest() throws MessagingException, PGPException, IOException {
        MimeMessage mimeMessage = prepareMimeMessage("image.png", "image/png");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        assertThrows(Exception.class, () -> mimeMessage.writeTo(byteArrayOutputStream));
        String rawMimeMessage = byteArrayOutputStream.toString();
        assertEquals("", rawMimeMessage);
    }

    private MimeMessage prepareMimeMessage(String fileName, String contentType)
            throws IOException, PGPException, MessagingException {
        String someText = "some text";
        String subject = "some subject";
        String sender = "default@flowcrypt.test";
        String receiver = "denbond7@flowcrypt.test";

        MimeMessage mimeMessage = new MimeMessage(Session.getDefaultInstance(new Properties()));
        mimeMessage.setFrom(sender);
        mimeMessage.setRecipients(Message.RecipientType.TO, receiver);
        mimeMessage.setSubject(subject);

        Multipart multipart = new MimeMultipart();
        multipart.addBodyPart(prepareTextPart(someText));
        multipart.addBodyPart(prepareAttachmentBodyPart(fileName, contentType));
        mimeMessage.setContent(multipart);
        return mimeMessage;
    }

    private MimeBodyPart prepareAttachmentBodyPart(
            String fileName,
            String contentType)
            throws IOException, MessagingException, PGPException {
        //prepare keys and SecretKeyRingProtector
        SecretKeyRingProtector secretKeyRingProtector =
                SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(PASSPHRASE));
        PGPPublicKeyRingCollection pgpPublicKeyRingCollection = PGPainless.readKeyRing().publicKeyRingCollection(
                SENDER_PUBLIC_KEY + "\n" + RECEIVER_PUBLIC_KEY);
        PGPSecretKeyRingCollection secretKeyRingCollection =
                PGPainless.readKeyRing().secretKeyRingCollection(SENDER_PRIVATE_KEY);

        ByteArrayOutputStream outputStreamForEncryptedBytes = new ByteArrayOutputStream();
        //open a file from resources and encrypt it
        try (InputStream inputStream = requireResource(fileName)) {
            EncryptionOptions encryptionOptions = new EncryptionOptions();
            encryptionOptions.addRecipients(pgpPublicKeyRingCollection);
            ProducerOptions producerOptions = ProducerOptions.encrypt(encryptionOptions);
            producerOptions.setAsciiArmor(false);

            try (EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(outputStreamForEncryptedBytes)
                    .withOptions(producerOptions)) {
                Streams.pipeAll(inputStream, encryptionStream);
            }
        }
        MimeBodyPart attachmentBodyPart = new MimeBodyPart();
        attachmentBodyPart.setDataHandler(new DataHandler(new DataSource() {
            @Override
            public InputStream getInputStream() throws IOException {
                try {
                    return PGPainless.decryptAndOrVerify()
                            .onInputStream(new ByteArrayInputStream(outputStreamForEncryptedBytes.toByteArray()))
                            .withOptions(
                                    new ConsumerOptions()
                                            .addDecryptionKeys(secretKeyRingCollection, secretKeyRingProtector)
                                            .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.THROW_EXCEPTION)
                            );
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public OutputStream getOutputStream() {
                return null;
            }

            @Override
            public String getContentType() {
                return contentType;
            }

            @Override
            public String getName() {
                return fileName;
            }
        }));
        attachmentBodyPart.setFileName(fileName);
        attachmentBodyPart.setContentID(UUID.randomUUID().toString());
        return attachmentBodyPart;
    }

    private BodyPart prepareTextPart(String someText) throws MessagingException {
        BodyPart bodyPart = new MimeBodyPart();
        bodyPart.setText(someText);
        return bodyPart;
    }

    private InputStream requireResource(String resourceName) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(resourceName);
        if (inputStream == null) {
            throw new TestAbortedException("Cannot read resource " + resourceName + ": InputStream is null.");
        }
        return inputStream;
    }
}
