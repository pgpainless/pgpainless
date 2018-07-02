/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.pgpainless;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.Ignore;
import org.pgpainless.pgpainless.key.SecretKeyRingProtector;
import org.pgpainless.pgpainless.key.UnprotectedKeysProtector;
import org.pgpainless.pgpainless.key.generation.type.length.RsaLength;
import org.pgpainless.pgpainless.util.BCUtil;

/**
 * Class used to determine the length of cipher-text depending on used algorithms.
 */
public class LengthTest extends AbstractPGPainlessTest {

    private static final Logger LOGGER = Logger.getLogger(LengthTest.class.getName());

    // @Test
    public void ecEc()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        LOGGER.log(Level.INFO, "\nEC -> EC");
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("simplejid@server.tld");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("otherjid@other.srv");
        encryptDecryptForSecretKeyRings(sender, recipient);
    }


    // @Test
    public void RsaRsa()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        LOGGER.log(Level.INFO, "\nRSA-2048 -> RSA-2048");
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("simplejid@server.tld", RsaLength._2048);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("otherjid@other.srv", RsaLength._2048);
        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    // @Test
    public void RsaRsa4096()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        LOGGER.log(Level.INFO, "\nRSA-4096 -> RSA-4096");
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("simplejid@server.tld", RsaLength._4096);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("otherjid@other.srv", RsaLength._4096);
        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    // @Test
    public void rsaEc() throws PGPException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        LOGGER.log(Level.INFO, "\nRSA-2048 -> EC");
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("simplejid@server.tld", RsaLength._2048);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("otherjid@other.srv");
        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    // @Test
    public void ecRsa()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        LOGGER.log(Level.INFO, "\nEC -> RSA-2048");
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("simplejid@server.tld");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("otherjid@other.srv", RsaLength._2048);
        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Ignore
    private void encryptDecryptForSecretKeyRings(PGPSecretKeyRing sender, PGPSecretKeyRing recipient)
            throws PGPException,
            IOException {
        PGPPublicKeyRing recipientPub = BCUtil.publicKeyRingFromSecretKeyRing(recipient);
        PGPPublicKeyRing senderPub = BCUtil.publicKeyRingFromSecretKeyRing(sender);

        SecretKeyRingProtector keyDecryptor = new UnprotectedKeysProtector();

        for (int i = 1; i <= 100; i++) {
            byte[] secretMessage = new byte[i * 20];
            new Random().nextBytes(secretMessage);

            ByteArrayOutputStream envelope = new ByteArrayOutputStream();

            OutputStream encryptor = PGPainless.createEncryptor()
                    .onOutputStream(envelope)
                    .toRecipients(recipientPub)
                    // .doNotEncrypt()
                    .usingSecureAlgorithms()
                    .signWith(keyDecryptor, sender)
                    .noArmor();

            Streams.pipeAll(new ByteArrayInputStream(secretMessage), encryptor);
            encryptor.close();
            byte[] encryptedSecretMessage = envelope.toByteArray();

            LOGGER.log(Level.INFO,"\n" + encryptedSecretMessage.length);
        }
    }
}
