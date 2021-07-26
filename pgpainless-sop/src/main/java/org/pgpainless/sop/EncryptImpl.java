/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.StreamUtil;
import sop.Ready;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;
import sop.util.ProxyOutputStream;

public class EncryptImpl implements Encrypt {

    EncryptionOptions encryptionOptions = new EncryptionOptions();
    SigningOptions signingOptions = null;

    private EncryptAs encryptAs = EncryptAs.Binary;
    boolean armor = true;

    @Override
    public Encrypt noArmor() {
        armor = false;
        return this;
    }

    @Override
    public Encrypt mode(EncryptAs mode) throws SOPGPException.UnsupportedOption {
        this.encryptAs = mode;
        return this;
    }

    @Override
    public Encrypt signWith(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.CertCannotSign, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        try {
            PGPSecretKeyRingCollection keys = PGPainless.readKeyRing().secretKeyRingCollection(keyIn);

            if (signingOptions == null) {
                signingOptions = SigningOptions.get();
            }
            try {
                signingOptions.addInlineSignatures(SecretKeyRingProtector.unprotectedKeys(), keys, DocumentSignatureType.BINARY_DOCUMENT);
            } catch (IllegalArgumentException e) {
                throw new SOPGPException.CertCannotSign();
            } catch (WrongPassphraseException e) {
                throw new SOPGPException.KeyIsProtected();
            }
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Encrypt withPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        encryptionOptions.addPassphrase(Passphrase.fromPassword(password));
        return this;
    }

    @Override
    public Encrypt withCert(InputStream cert) throws SOPGPException.CertCannotEncrypt, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        try {
            PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing()
                    .keyRingCollection(cert, false)
                    .getPgpPublicKeyRingCollection();
            encryptionOptions.addRecipients(certificates);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Ready plaintext(InputStream plaintext) throws IOException {
        ProducerOptions producerOptions = signingOptions != null ?
                ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions) :
                ProducerOptions.encrypt(encryptionOptions);
        producerOptions.setAsciiArmor(armor);
        producerOptions.setEncoding(encryptAsToStreamEncoding(encryptAs));

        try {
            ProxyOutputStream proxy = new ProxyOutputStream();
            EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(proxy)
                    .withOptions(producerOptions);

            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {
                    proxy.replaceOutputStream(outputStream);
                    StreamUtil.pipeAll(plaintext, encryptionStream);
                    encryptionStream.close();
                }
            };
        } catch (PGPException e) {
            throw new IOException();
        }
    }

    private static StreamEncoding encryptAsToStreamEncoding(EncryptAs encryptAs) {
        switch (encryptAs) {
            case Binary:
                return StreamEncoding.BINARY;
            case Text:
                return StreamEncoding.TEXT;
            case MIME:
                return StreamEncoding.UTF8;
        }
        throw new IllegalArgumentException("Invalid value encountered: " + encryptAs);
    }
}
