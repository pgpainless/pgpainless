// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.util.Passphrase;
import sop.Ready;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;
import sop.util.ProxyOutputStream;

public class EncryptImpl implements Encrypt {

    EncryptionOptions encryptionOptions = new EncryptionOptions();
    SigningOptions signingOptions = null;
    MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
    private final Set<PGPSecretKeyRing> signingKeys = new HashSet<>();

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
    public Encrypt signWith(InputStream keyIn)
            throws SOPGPException.KeyCannotSign, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        if (signingOptions == null) {
            signingOptions = SigningOptions.get();
        }

        try {
            PGPSecretKeyRingCollection keys = PGPainless.readKeyRing().secretKeyRingCollection(keyIn);
            if (keys.size() != 1) {
                throw new SOPGPException.BadData(new AssertionError("Exactly one secret key at a time expected. Got " + keys.size()));
            }
            PGPSecretKeyRing signingKey = keys.iterator().next();

            KeyRingInfo info = PGPainless.inspectKeyRing(signingKey);
            if (info.getSigningSubkeys().isEmpty()) {
                throw new SOPGPException.KeyCannotSign("Key " + OpenPgpFingerprint.of(signingKey) + " cannot sign.");
            }

            protector.addSecretKey(signingKey);
            signingKeys.add(signingKey);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Encrypt withKeyPassword(byte[] password) {
        String passphrase = new String(password, Charset.forName("UTF8"));
        protector.addPassphrase(Passphrase.fromPassword(passphrase));
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
        } catch (KeyException.UnacceptableEncryptionKeyException e) {
            throw new SOPGPException.CertCannotEncrypt(e.getMessage(), e);
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

        for (PGPSecretKeyRing signingKey : signingKeys) {
            try {
                signingOptions.addInlineSignature(
                        protector,
                        signingKey,
                        (encryptAs == EncryptAs.Binary ? DocumentSignatureType.BINARY_DOCUMENT : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                );
            } catch (KeyException.UnacceptableSigningKeyException e) {
                throw new SOPGPException.KeyCannotSign();
            } catch (WrongPassphraseException e) {
                throw new SOPGPException.KeyIsProtected();
            } catch (PGPException e) {
                throw new SOPGPException.BadData(e);
            }
        }

        try {
            ProxyOutputStream proxy = new ProxyOutputStream();
            EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(proxy)
                    .withOptions(producerOptions);

            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {
                    proxy.replaceOutputStream(outputStream);
                    Streams.pipeAll(plaintext, encryptionStream);
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
                return StreamEncoding.UTF8;
        }
        throw new IllegalArgumentException("Invalid value encountered: " + encryptAs);
    }
}
