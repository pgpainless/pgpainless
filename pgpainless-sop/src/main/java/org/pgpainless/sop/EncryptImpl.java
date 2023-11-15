// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
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
import sop.EncryptionResult;
import sop.Profile;
import sop.ReadyWithResult;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;
import sop.util.ProxyOutputStream;
import sop.util.UTF8Util;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>encrypt</pre> operation using PGPainless.
 */
public class EncryptImpl implements Encrypt {

    private static final Profile RFC4880_PROFILE = new Profile("rfc4880", "Follow the packet format of rfc4880");

    public static final List<Profile> SUPPORTED_PROFILES = Arrays.asList(RFC4880_PROFILE);

    EncryptionOptions encryptionOptions = EncryptionOptions.get();
    SigningOptions signingOptions = null;
    MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
    private final Set<PGPSecretKeyRing> signingKeys = new HashSet<>();
    private String profile = RFC4880_PROFILE.getName(); // TODO: Use in future releases

    private EncryptAs encryptAs = EncryptAs.binary;
    boolean armor = true;

    @Nonnull
    @Override
    public Encrypt noArmor() {
        armor = false;
        return this;
    }

    @Nonnull
    @Override
    public Encrypt mode(@Nonnull EncryptAs mode) throws SOPGPException.UnsupportedOption {
        this.encryptAs = mode;
        return this;
    }

    @Nonnull
    @Override
    public Encrypt signWith(@Nonnull InputStream keyIn)
            throws SOPGPException.KeyCannotSign, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData, IOException {
        if (signingOptions == null) {
            signingOptions = SigningOptions.get();
        }
        PGPSecretKeyRingCollection keys = KeyReader.readSecretKeys(keyIn, true);
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
        return this;
    }

    @Nonnull
    @Override
    public Encrypt withKeyPassword(@Nonnull byte[] password) {
        String passphrase = new String(password, UTF8Util.UTF8);
        protector.addPassphrase(Passphrase.fromPassword(passphrase));
        return this;
    }

    @Nonnull
    @Override
    public Encrypt withPassword(@Nonnull String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        encryptionOptions.addPassphrase(Passphrase.fromPassword(password));
        return this;
    }

    @Nonnull
    @Override
    public Encrypt withCert(@Nonnull InputStream cert) throws SOPGPException.CertCannotEncrypt, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        try {
            PGPPublicKeyRingCollection certificates = KeyReader.readPublicKeys(cert, true);
            encryptionOptions.addRecipients(certificates);
        } catch (KeyException.UnacceptableEncryptionKeyException e) {
            throw new SOPGPException.CertCannotEncrypt(e.getMessage(), e);
        } catch (IOException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Nonnull
    @Override
    public Encrypt profile(@Nonnull String profileName) {
        // sanitize profile name to make sure we only accept supported profiles
        for (Profile profile : SUPPORTED_PROFILES) {
            if (profile.getName().equals(profileName)) {
                // profile is supported, return
                this.profile = profile.getName();
                return this;
            }
        }

        // Profile is not supported, throw
        throw new SOPGPException.UnsupportedProfile("encrypt", profileName);
    }

    @Nonnull
    @Override
    public ReadyWithResult<sop.EncryptionResult> plaintext(@Nonnull InputStream plaintext) throws IOException {
        if (!encryptionOptions.hasEncryptionMethod()) {
            throw new SOPGPException.MissingArg("Missing encryption method.");
        }
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
                        (encryptAs == EncryptAs.binary ? DocumentSignatureType.BINARY_DOCUMENT : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
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

            return new ReadyWithResult<EncryptionResult>() {
                @Override
                public EncryptionResult writeTo(@Nonnull OutputStream outputStream) throws IOException {
                    proxy.replaceOutputStream(outputStream);
                    Streams.pipeAll(plaintext, encryptionStream);
                    encryptionStream.close();
                    // TODO: Extract and emit SessionKey
                    return new EncryptionResult(null);
                }
            };
        } catch (PGPException e) {
            throw new IOException();
        }
    }

    private static StreamEncoding encryptAsToStreamEncoding(EncryptAs encryptAs) {
        switch (encryptAs) {
            case binary:
                return StreamEncoding.BINARY;
            case text:
                return StreamEncoding.UTF8;
        }
        throw new IllegalArgumentException("Invalid value encountered: " + encryptAs);
    }
}
